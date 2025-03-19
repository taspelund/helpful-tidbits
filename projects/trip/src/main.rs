use byteorder::{BigEndian, ReadBytesExt};
use ipnet::{Ipv4Net, Ipv6Net};
use socket2::{self, Domain, InterfaceIndexOrAddress, SockAddr, Socket, Type};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::CString,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    str::FromStr,
    sync::{Arc, Mutex},
};

/// Constants for `RIPv2` sockets
const RIPV2_PORT: u16 = 520;
const RIPV2_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RIPV2_PORT));
const RIPV2_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
const RIPV2_DEST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(RIPV2_GROUP, RIPV2_PORT));
/// Constants for `RIPng` sockets
const RIPNG_PORT: u16 = 521;
const RIPNG_BIND: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, RIPNG_PORT, 0, 0));
const RIPNG_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9);
const RIPNG_DEST: SocketAddr = SocketAddr::V6(SocketAddrV6::new(RIPNG_GROUP, RIPNG_PORT, 0, 0));
/// Constants for header lengths and packet sizes
// XXX: query link MTU from kernel
const ASSUMED_MTU: usize = 1500;
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
const UDP_HEADER_LEN: usize = 8;
const RIP_HEADER_LEN: usize = 4;
const RIP_PKT_MAX_LEN: usize = ASSUMED_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN;
// const RIP_PKT_MAX_RTE: usize = RIP_PKT_MAX_LEN / RouteTableEntry::SIZE;
const RIPNG_PKT_MAX_LEN: usize = ASSUMED_MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN;
// const RIPNG_PKT_MAX_RTE: usize = RIPNG_PKT_MAX_LEN / RouteTableEntry::SIZE;

/// `RIP` packet structure. Applicable to both `RIPv2` and `RIPng`.
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |  command (1)  |  version (1)  |       must be zero (2)        |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                Route Table Entry 1 (20)                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                         ...                                   ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                Route Table Entry N (20)                       ~
/// |                                                               |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
struct RipPacket {
    cmd: RipCommand, // header start
    ver: u8,
    mbz: u16,
    rt_entries: Vec<RouteTableEntry>, // payload start
}

impl RipPacket {
    const INFINITY_METRIC: u8 = 16;

    fn new(cmd: RipCommand, proto: &RipVersion, rt_entries: Vec<RouteTableEntry>) -> RipPacket {
        Self {
            cmd,
            ver: proto.to_u8(),
            mbz: 0u16,
            rt_entries,
        }
    }

    fn from_bytes(proto: &RipVersion, b: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(b);

        // START HEADER
        let c = cursor.read_u8()?;
        let Some(cmd) = RipCommand::from_u8(c) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported RIP command: {c}"),
            ));
        };

        let ver = cursor.read_u8()?;
        if ver != proto.to_u8() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid RIP version. Expected ({}), Received ({ver})",
                    proto.to_u8()
                ),
            ));
        }

        let mbz = cursor.read_u16::<BigEndian>()?;
        if mbz != 0 {
            // RFCs 2453 (RIPv2) and 2080 (RIPng) don't state what to do here.
            // It seems sane to log this and otherwise ignore it.
            eprintln!("must-be-zero field is not set to zero: {mbz}");
        } // END HEADER

        let total_len = b.len();
        let header_len = cursor.position() as usize;
        let payload_len = total_len - header_len;
        if payload_len % RouteTableEntry::SIZE != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid payload length. Payload must be a multiple of {}, found {payload_len}",
                    RouteTableEntry::SIZE
                ),
            ));
        }

        let num_rtes = payload_len / RouteTableEntry::SIZE;
        let mut rt_entries: Vec<RouteTableEntry> = Vec::with_capacity(num_rtes);
        for _ in 0..num_rtes {
            let start = cursor.position() as usize;
            let end = start + RouteTableEntry::SIZE;
            let rte_bytes = &b[start..end];
            match RouteTableEntry::from_bytes(proto, rte_bytes) {
                Ok(rte) => rt_entries.push(rte),
                Err(e) => eprintln!("Error parsing RTE: {e}"),
            }
            cursor.set_position(end as u64);
        }

        Ok(RipPacket {
            cmd,
            ver,
            mbz,
            rt_entries,
        })
    }

    fn to_byte_vec(&self) -> Vec<u8> {
        let mut b = Vec::<u8>::new();
        b.push(self.cmd.to_u8()); // single byte, no order
        b.push(self.ver); // single byte, no order
        b.extend_from_slice(&self.mbz.to_be_bytes());
        for rte in &self.rt_entries {
            b.extend_from_slice(&rte.to_bytes());
        }
        b
    }

    fn process(&mut self, db: &mut RipDb, src: IpAddr) {
        let mut nh: Option<Ipv6Addr> = None;
        for rte in &mut self.rt_entries {
            match rte {
                RouteTableEntry::Ipv4Prefix(prefix4) => {
                    let rpi = RipPathInfo {
                        nh: match prefix4.nh.is_unspecified() {
                            true => src,
                            false => IpAddr::V4(prefix4.nh),
                        },
                        ifindex: 0u32,
                        metric: prefix4.metric as u8,
                        tag: prefix4.tag,
                    };
                    let mut rib = db.ripv2_rib.lock().unwrap();
                    let nh_set = rib.entry(prefix4.prefix()).or_insert(BTreeSet::new());
                    nh_set.insert(rpi);
                }
                RouteTableEntry::Ipv4Authentication(auth4) => {
                    // XXX: set auth here (need access to rif.set_auth_pw())
                    println!("{auth4:?}");
                    ()
                }
                RouteTableEntry::Ipv6Prefix(prefix6) => {
                    let rpi = RipPathInfo {
                        nh: match nh {
                            None => src,
                            Some(n) => {
                                if n.is_unspecified() {
                                    src
                                } else {
                                    IpAddr::V6(n)
                                }
                            }
                        },
                        ifindex: 0u32,
                        metric: prefix6.metric as u8,
                        tag: prefix6.tag,
                    };
                    let mut rib = db.ripng_rib.lock().unwrap();
                    let nh_set = rib.entry(prefix6.prefix()).or_insert(BTreeSet::new());
                    nh_set.insert(rpi);
                }
                RouteTableEntry::Ipv6Nexthop(nexthop6) => nh = Some(nexthop6.nh),
            }
        }
    }
}

impl std::fmt::Display for RipPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "RipPacket {{\n\tcmd: {},\n\tver: 0x{:x},\n\tmbz: 0x{:x},\n\trt_entries: (\n{}\n\t)\n}}",
            self.cmd,
            self.ver,
            self.mbz,
            self.rt_entries
                .iter()
                .map(|rte| format!("\t\t[{rte}]"))
                .collect::<Vec<_>>()
                .join(",\n")
        )
    }
}

/// RIP message type
#[derive(Clone, Debug, PartialEq, Eq)]
enum RipCommand {
    Request = 1,
    Response = 2,
}

impl RipCommand {
    fn to_u8(&self) -> u8 {
        self.clone() as u8
    }

    fn from_u8(n: u8) -> Option<Self> {
        match n {
            1 => Some(Self::Request),
            2 => Some(Self::Response),
            _ => None,
        }
    }
}

impl std::fmt::Display for RipCommand {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Request => "REQUEST",
                Self::Response => "RESPONSE",
            }
        )
    }
}

/// `RIP` version numbers
#[allow(clippy::upper_case_acronyms)]
#[derive(Clone, PartialEq, Eq)]
enum RipVersion {
    RIP = 2,
    RIPng = 1,
}

impl RipVersion {
    fn to_u8(&self) -> u8 {
        self.clone() as u8
    }
}

/// `RIPv2` Address-Family Identifiers
#[derive(Clone, Debug, PartialEq, Eq)]
enum RipV2AddressFamily {
    Inet = 0x0002,
    Auth = 0xFFFF,
}

impl std::fmt::Display for RipV2AddressFamily {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Inet => Self::AFI_INET_STR,
                Self::Auth => Self::AFI_AUTH_STR,
            }
        )
    }
}

impl RipV2AddressFamily {
    const AFI_INET_STR: &str = "AFI_INET";
    const AFI_AUTH_STR: &str = "AFI_AUTH";

    fn from_u16(n: u16) -> Option<Self> {
        match n {
            0x0002 => Some(Self::Inet),
            0xFFFF => Some(Self::Auth),
            _ => None,
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            Self::Inet => 0x0002,
            Self::Auth => 0xFFFF,
        }
    }
}

/// `RIPv2` Authentication Types
#[derive(Clone, Debug, PartialEq, Eq)]
enum RipV2AuthType {
    Password = 0x0002,
}

impl std::fmt::Display for RipV2AuthType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::Password => Self::AUTH_TYPE_PW_STR,
            }
        )
    }
}

impl RipV2AuthType {
    const AUTH_TYPE_PW_STR: &str = "AUTH_TYPE_PASSWORD";

    fn from_u16(n: u16) -> Option<Self> {
        match n {
            0x0002 => Some(Self::Password),
            _ => None,
        }
    }

    fn to_u16(&self) -> u16 {
        self.clone() as u16
    }
}

/// Route Table Entry Types
#[derive(Clone, Debug)]
enum RouteTableEntry {
    Ipv4Prefix(Rte4Prefix),
    Ipv4Authentication(Rte4Auth),
    Ipv6Prefix(Rte6Prefix),
    Ipv6Nexthop(Rte6Nexthop),
}

impl RouteTableEntry {
    // All RTEs are the same length, across all RTE types & RIP Protocol versions
    const SIZE: usize = 20;
    // RIPNg RTE with metric == 0xFF carries a nexthop
    const RIPNG_METRIC_NEXTHOP: u8 = u8::MAX;

    fn from_bytes(ver: &RipVersion, b: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(b);
        match ver {
            RipVersion::RIP => {
                let af = cursor.read_u16::<BigEndian>()?;
                match RipV2AddressFamily::from_u16(af) {
                    Some(afi) => match afi {
                        RipV2AddressFamily::Inet => {
                            let tag = cursor.read_u16::<BigEndian>()?;
                            let addr = Ipv4Addr::from_bits(cursor.read_u32::<BigEndian>()?);
                            let mask = cursor.read_u32::<BigEndian>()?;
                            let nh = Ipv4Addr::from_bits(cursor.read_u32::<BigEndian>()?);
                            let metric = cursor.read_u32::<BigEndian>()?;

                            if addr.is_loopback() || addr.is_multicast() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "Invalid Prefix {addr}: cannot be multicast or loopback range"
                                    ),
                                ));
                            }

                            if mask.leading_ones() > Ipv4Addr::BITS {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                    "Invalid Mask {mask}: cannot be greater than IPv4 bit length ({})",
                                    Ipv4Addr::BITS
                                ),
                                ));
                            }

                            if nh.is_loopback() || nh.is_multicast() {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                    "Invalid Nexthop {nh}: cannot be multicast or loopback address"
                                    ),
                                ));
                            }

                            if metric > u32::from(RipPacket::INFINITY_METRIC) {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!(
                                        "Invalid Metric {metric}: cannot be greater than infinity ({})",
                                        RipPacket::INFINITY_METRIC
                                    ),
                                ));
                            }

                            Ok(Self::Ipv4Prefix(Rte4Prefix {
                                afi,
                                tag,
                                addr,
                                mask,
                                nh,
                                metric,
                            }))
                        }
                        RipV2AddressFamily::Auth => {
                            let at = cursor.read_u16::<BigEndian>()?;
                            let pw = cursor.read_u128::<BigEndian>()?;

                            // XXX: Discard entire RipPacket if auth is bad,
                            // i.e.
                            // 1) auth enabled but rx pkt has no/incorrect auth
                            // 2) auth disabled but rx pkt has auth
                            let Some(auth_type) = RipV2AuthType::from_u16(at) else {
                                return Err(std::io::Error::new(
                                    std::io::ErrorKind::InvalidData,
                                    format!("Unsupported RIPv2 Authentication Type: {at}"),
                                ));
                            };

                            Ok(Self::Ipv4Authentication(Rte4Auth { afi, auth_type, pw }))
                        }
                    },

                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unsupported RIPv2 Address Family: {af}"),
                    )),
                }
            }
            RipVersion::RIPng => {
                let pfx = Ipv6Addr::from_bits(cursor.read_u128::<BigEndian>()?);
                let tag = cursor.read_u16::<BigEndian>()?;
                let pfx_len = cursor.read_u8()?;
                let metric = cursor.read_u8()?;

                match metric {
                    RouteTableEntry::RIPNG_METRIC_NEXTHOP => {
                        if pfx.is_multicast() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Invalid Nexthop ({pfx}): must be unicast"),
                            ));
                        }

                        Ok(Self::Ipv6Nexthop(Rte6Nexthop {
                            nh: pfx,
                            mbz1: tag,
                            mbz2: pfx_len,
                            metric,
                        }))
                    }
                    // RTE with a valid metric carries a prefix
                    0..=RipPacket::INFINITY_METRIC => {
                        if pfx.is_multicast() || pfx.is_loopback() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "Invalid Prefix {pfx}: cannot be multicast or loopback range"
                                ),
                            ));
                        }

                        if pfx_len > u8::try_from(Ipv6Addr::BITS).unwrap() {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!(
                                    "Invalid Prefix Length {pfx}: cannot be greater than IPv6 bit length {}",
                                    Ipv6Addr::BITS
                                ),
                            ));
                        }

                        Ok(Self::Ipv6Prefix(Rte6Prefix {
                            pfx,
                            tag,
                            pfx_len,
                            metric,
                        }))
                    }
                    _ => {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            format!(
                                "Invalid metric {metric}: cannot be greater than infinity ({})",
                                RipPacket::INFINITY_METRIC
                            ),
                        ));
                    }
                }
            }
        }
    }

    fn to_bytes(&self) -> [u8; RouteTableEntry::SIZE] {
        let mut b = [0u8; RouteTableEntry::SIZE];
        match self {
            Self::Ipv4Prefix(prefix4) => {
                b[0..=1].copy_from_slice(&prefix4.afi.to_u16().to_be_bytes());
                b[2..=3].copy_from_slice(&prefix4.tag.to_be_bytes());
                b[4..=7].copy_from_slice(&prefix4.addr.to_bits().to_be_bytes());
                b[8..=11].copy_from_slice(&prefix4.mask.to_be_bytes());
                b[12..=15].copy_from_slice(&prefix4.nh.to_bits().to_be_bytes());
                b[16..=19].copy_from_slice(&prefix4.metric.to_be_bytes());
                b
            }
            Self::Ipv4Authentication(auth4) => {
                b[0..=1].copy_from_slice(&auth4.afi.to_u16().to_be_bytes());
                b[2..=3].copy_from_slice(&auth4.auth_type.to_u16().to_be_bytes());
                b[4..=19].copy_from_slice(&auth4.pw.to_be_bytes());
                b
            }
            Self::Ipv6Prefix(prefix6) => {
                b[0..=15].copy_from_slice(&prefix6.pfx.to_bits().to_be_bytes());
                b[16..=17].copy_from_slice(&prefix6.tag.to_be_bytes());
                b[18] = prefix6.pfx_len;
                b[19] = prefix6.metric;
                b
            }
            Self::Ipv6Nexthop(nexthop6) => {
                b[0..=15].copy_from_slice(&nexthop6.nh.to_bits().to_be_bytes());
                b[16..=17].copy_from_slice(&nexthop6.mbz1.to_be_bytes());
                b[18] = nexthop6.mbz2;
                b[19] = nexthop6.metric;
                b
            }
        }
    }
}

impl std::fmt::Display for RouteTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteTableEntry::Ipv4Prefix(prefix4) => {
                write!(
                    f,
                    "Rte4Prefix {{ afi: {}, tag: {}, addr: {}, mask: {}, nh: {}, metric: {} }}",
                    prefix4.afi,
                    prefix4.tag,
                    prefix4.addr,
                    Ipv4Addr::from_bits(prefix4.mask),
                    prefix4.nh,
                    prefix4.metric
                )
            }
            RouteTableEntry::Ipv4Authentication(auth4) => {
                write!(
                    f,
                    "Rte4Auth {{ afi: {}, auth_type: {}, pw: {:x?} }}",
                    auth4.afi,
                    auth4.auth_type,
                    auth4.pw.to_be_bytes(),
                )
            }
            RouteTableEntry::Ipv6Prefix(prefix6) => {
                write!(
                    f,
                    "Rte6Prefix {{ pfx: {:x?}, tag: {}, pfx_len: {}, metric: {} }}",
                    prefix6.pfx, prefix6.tag, prefix6.pfx_len, prefix6.metric
                )
            }
            RouteTableEntry::Ipv6Nexthop(nexthop6) => {
                write!(
                    f,
                    "Rte6Nexthop {{ nh: {:x?}, mbz1: {}, mbz2: {}, metric: {} }}",
                    nexthop6.nh, nexthop6.mbz1, nexthop6.mbz2, nexthop6.metric,
                )
            }
        }
    }
}

/// `RIPv2` Standard Route Entry: contains prefix.
///  0                   1                   2                   3 3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Address Family Identifier (2) |        Route Tag (2)          |
/// +-------------------------------+-------------------------------+
/// |                         IP Address (4)                        |
/// +---------------------------------------------------------------+
/// |                         Subnet Mask (4)                       |
/// +---------------------------------------------------------------+
/// |                         Next Hop (4)                          |
/// +---------------------------------------------------------------+
/// |                         Metric (4)                            |
/// +---------------------------------------------------------------+
#[derive(Clone, Debug)]
struct Rte4Prefix {
    afi: RipV2AddressFamily, // 2 bytes
    tag: u16,                // + 2 bytes = 4
    addr: Ipv4Addr,          // + 4 bytes = 8
    mask: u32,               // + 4 bytes = 12
    nh: Ipv4Addr,            // + 4 bytes = 16
    // u8 value encoded as u32
    metric: u32, // + 4 bytes = 20
}

impl Rte4Prefix {
    fn prefix(&self) -> Ipv4Net {
        Ipv4Net::new_assert(
            self.addr,
            u8::try_from(self.mask.leading_ones())
                .expect("mask > {u8::MAX}, so u8 conversion failed"),
        )
        .trunc()
    }
}

/// `RIPv2` Authentication Route Entry: contains auth instead of prefix, AFI = 0xFFFF
///  0                   1                   2                   3 3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// | Command (1)   | Version (1)   |            unused             |
/// +---------------+---------------+-------------------------------+
/// |             0xFFFF            |    Authentication Type (2)    |
/// +-------------------------------+-------------------------------+
/// ~                       Authentication (16)                     ~
/// +---------------------------------------------------------------+
#[derive(Clone, Debug)]
struct Rte4Auth {
    afi: RipV2AddressFamily,
    auth_type: RipV2AuthType,
    pw: u128,
}

/// `RIPng` Standard Route Entry: contains prefix.
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                        IPv6 prefix (16)                       ~
/// |                                                               |
/// +---------------------------------------------------------------+
/// |         route tag (2)         | prefix len (1)|  metric (1)   |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug)]
struct Rte6Prefix {
    pfx: Ipv6Addr,
    tag: u16,
    pfx_len: u8,
    metric: u8,
}

impl Rte6Prefix {
    fn prefix(&self) -> Ipv6Net {
        Ipv6Net::new_assert(self.pfx, self.pfx_len).trunc()
    }
}

/// `RIPng` Standard Route Entry: contains next hop, metric = 0xFF
///  0                   1                   2                   3
///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// |                                                               |
/// ~                    IPv6 next hop address (16)                 ~
/// |                                                               |
/// +---------------------------------------------------------------+
/// |        must be zero (2)       |must be zero(1)|     0xFF      |
/// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug)]
struct Rte6Nexthop {
    nh: Ipv6Addr,
    mbz1: u16,
    mbz2: u8,
    metric: u8, // always set to u8::MAX
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RipPathInfo {
    nh: IpAddr,
    ifindex: u32,
    metric: u8,
    tag: u16,
}

impl Ord for RipPathInfo {
    fn cmp(&self, other: &Self) -> Ordering {
        if self.nh != other.nh {
            return self.nh.cmp(&other.nh);
        }
        self.ifindex.cmp(&other.ifindex)
    }
}

impl PartialOrd for RipPathInfo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Clone, Debug)]
struct RipDb {
    ripv2_rib: Arc<Mutex<BTreeMap<Ipv4Net, BTreeSet<RipPathInfo>>>>,
    ripng_rib: Arc<Mutex<BTreeMap<Ipv6Net, BTreeSet<RipPathInfo>>>>,
}

impl RipDb {
    fn new() -> Self {
        Self {
            ripv2_rib: Arc::new(Mutex::new(BTreeMap::new())),
            ripng_rib: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }
}

fn ifname_to_ifindex(ifname: &str) -> Result<u32, std::ffi::NulError> {
    let ifindex = unsafe {
        let ifstr = CString::new(ifname)?.into_raw();
        let ifindex = libc::if_nametoindex(ifstr) as u32;
        drop(CString::from_raw(ifstr));
        ifindex
    };
    Ok(ifindex)
}

struct RipInterface {
    // XXX: Convert to &str and learn lifetimes?
    ifname: String,
    ifindex: u32,
    ripv2_sock: Option<UdpSocket>,
    ripng_sock: Option<UdpSocket>,
    auth: Option<(RipV2AuthType, u128)>,
}

impl RipInterface {
    fn new(ifname: String) -> Option<Self> {
        let ifindex = ifname_to_ifindex(&ifname).ok()?;
        Some(Self {
            ifname,
            ifindex,
            ripv2_sock: None,
            ripng_sock: None,
            auth: None,
        })
    }

    fn enable_ripv2(&mut self) -> std::io::Result<()> {
        let ripv2_sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
        ripv2_sock.set_reuse_address(true)?;
        ripv2_sock.bind_device(Some(self.ifname.as_bytes()))?;
        ripv2_sock.bind(&SockAddr::from(RIPV2_BIND))?;
        ripv2_sock.set_multicast_all_v4(true)?;
        // ripv2_sock.set_multicast_if_v4(&V4_IFADDR)?;
        // XXX: we may want to disable this at some point
        ripv2_sock.set_multicast_loop_v4(true)?;
        ripv2_sock
            .join_multicast_v4_n(&RIPV2_GROUP, &InterfaceIndexOrAddress::Index(self.ifindex))?;
        // for whatever reason, the socket doesn't rx packets sent to 224.0.0.9
        // if we call connect() against 224.0.0.9... so leave this unconnected for now?
        // ripv2_sock.connect(&SockAddr::from(RIPV2_DEST))?;
        self.ripv2_sock = Some(ripv2_sock.into());
        Ok(())
    }

    fn enable_ripng(&mut self) -> std::io::Result<()> {
        let ripng_sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
        ripng_sock.set_only_v6(true)?;
        ripng_sock.set_reuse_address(true)?;
        ripng_sock.bind_device(Some(self.ifname.as_bytes()))?;
        ripng_sock.bind(&SockAddr::from(RIPNG_BIND))?;
        ripng_sock.set_multicast_all_v6(true)?;
        // ripng_sock.set_multicast_if_v6(ifindex)?;
        // XXX: we may want to disable this at some point
        ripng_sock.set_multicast_loop_v6(true)?;
        ripng_sock.join_multicast_v6(&RIPNG_GROUP, self.ifindex)?;
        // for whatever reason, the socket doesn't rx packets sent to ff02::9
        // if we call connect() against ff02::9... so leave this unconnected for now?
        // ripng_sock.connect(&SockAddr::from(RIPNG_DEST))?;
        self.ripng_sock = Some(ripng_sock.into());
        Ok(())
    }

    fn set_auth_pw(&mut self, pw: u128) -> std::io::Result<()> {
        self.auth = Some((RipV2AuthType::Password, pw));
        Ok(())
    }

    fn send_ripv2(&self, rp: &RipPacket) {
        match self.ripv2_sock {
            None => return,
            Some(ref sock) => {
                // use send_to() instead of send() because the socket isn't connect()'d
                if let Ok(bytes_sent) = sock.send_to(&rp.to_byte_vec(), &RIPV2_DEST) {
                    println!(
                        "tx rip pkt ({bytes_sent} bytes) from {} to {}:\n{rp}\n",
                        sock.local_addr().unwrap(),
                        &RIPV2_DEST
                    );
                }
            }
        }
    }

    fn send_ripng(&self, rp: &RipPacket) {
        match self.ripng_sock {
            None => return,
            Some(ref sock) => {
                // use send_to() instead of send() because the socket isn't connect()'d
                if let Ok(bytes_sent) = sock.send_to(&rp.to_byte_vec(), &RIPNG_DEST) {
                    println!(
                        "tx rip pkt ({bytes_sent} bytes) from {} to {}:\n{rp}\n",
                        sock.local_addr().unwrap(),
                        &RIPNG_DEST
                    );
                }
            }
        }
    }
}

fn listen_ripv2(sock: &UdpSocket, db: &mut RipDb) {
    let mut buf = [0u8; 4096];
    println!(
        "listening for {} on {}",
        "RIPv2",
        sock.local_addr().unwrap(),
    );
    let max_len = RIP_PKT_MAX_LEN;
    loop {
        buf.fill(0);
        if let Ok((rx_bytes, src_addr)) = sock.recv_from(&mut buf) {
            println!(
                "rx {rx_bytes} bytes from {src_addr} -> {:x?}",
                &buf[0..rx_bytes]
            );

            if rx_bytes < RIP_HEADER_LEN {
                println!("data too short, must be >= {RIP_HEADER_LEN} bytes, rx {rx_bytes} bytes");
                continue;
            }

            if rx_bytes > max_len {
                println!(
                    "data too large, datagram must be >= {max_len} bytes, rx {rx_bytes} bytes"
                );
                continue;
            }

            match RipPacket::from_bytes(&RipVersion::RIP, &buf[..rx_bytes]) {
                Ok(mut rip_pkt) => {
                    println!("rx rip pkt ({rx_bytes} bytes) from {src_addr}:\n{rip_pkt}\n");
                    rip_pkt.process(db, src_addr.ip());
                    println!("RIPv2 RIB: {:#?}\n", db.ripv2_rib);
                }
                Err(e) => {
                    eprintln!("failed to parse rx bytes! {e}");
                    continue;
                }
            }
        } else {
            eprintln!("failed to read from listening socket!");
            break;
        }
    }
}

// XXX: figure out how to consolidate this in a sane way... possibly generics?
fn listen_ripng(sock: &UdpSocket, db: &mut RipDb) {
    let mut buf = [0u8; 4096];
    println!(
        "listening for {} on {}",
        "RIPv2",
        sock.local_addr().unwrap(),
    );
    let max_len = RIPNG_PKT_MAX_LEN;
    loop {
        buf.fill(0);
        if let Ok((rx_bytes, src_addr)) = sock.recv_from(&mut buf) {
            println!(
                "rx {rx_bytes} bytes from {src_addr} -> {:x?}",
                &buf[0..rx_bytes]
            );

            if rx_bytes < RIP_HEADER_LEN {
                println!("data too short, must be >= {RIP_HEADER_LEN} bytes, rx {rx_bytes} bytes");
                continue;
            }

            if rx_bytes > max_len {
                println!(
                    "data too large, datagram must be >= {max_len} bytes, rx {rx_bytes} bytes"
                );
                continue;
            }

            match RipPacket::from_bytes(&RipVersion::RIPng, &buf[..rx_bytes]) {
                Ok(mut rip_pkt) => {
                    println!("rx rip pkt ({rx_bytes} bytes) from {src_addr}:\n{rip_pkt}\n");
                    rip_pkt.process(db, src_addr.ip());
                    println!("RIPng RIB: {:#?}\n", db.ripng_rib);
                }
                Err(e) => {
                    eprintln!("failed to parse rx bytes! {e}");
                    continue;
                }
            }
        } else {
            eprintln!("failed to read from listening socket!");
            break;
        }
    }
}

const HELP: &str = "trip {sender <ifname> | listener <ifname>}";

fn main() -> std::io::Result<()> {
    let Some(ifname) = env::args().nth(2) else {
        eprintln!("ifname is a required argument!");
        eprintln!("{HELP}");
        return Ok(());
    };

    let Some(mode) = env::args().nth(1) else {
        eprintln!("run mode is a required argument!");
        eprintln!("{HELP}");
        return Ok(());
    };

    match mode.as_str() {
        "sender" => {
            let mut rif = RipInterface::new(ifname.clone()).unwrap();
            rif.enable_ripv2()?;
            rif.enable_ripng()?;

            let rte4_list = vec![
                RouteTableEntry::Ipv4Authentication(Rte4Auth {
                    afi: RipV2AddressFamily::Auth,
                    auth_type: RipV2AuthType::Password,
                    pw: 0u128,
                }),
                RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                    afi: RipV2AddressFamily::Inet,
                    tag: 50_u16,
                    addr: Ipv4Addr::from_str("10.1.1.1").unwrap(),
                    mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                    nh: Ipv4Addr::from_str("192.168.0.1").unwrap(),
                    metric: 5_u32,
                }),
                RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                    afi: RipV2AddressFamily::Inet,
                    tag: 100_u16,
                    addr: Ipv4Addr::from_str("20.0.0.0").unwrap(),
                    mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                    nh: Ipv4Addr::from_str("192.168.0.1").unwrap(),
                    metric: 10_u32,
                }),
                RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                    afi: RipV2AddressFamily::Inet,
                    tag: 150_u16,
                    addr: Ipv4Addr::from_str("30.0.0.0").unwrap(),
                    mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                    nh: Ipv4Addr::from_str("192.168.0.1").unwrap(),
                    metric: 15_u32,
                }),
                RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                    afi: RipV2AddressFamily::Inet,
                    tag: 150_u16,
                    addr: Ipv4Addr::from_str("30.0.0.0").unwrap(),
                    mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                    nh: Ipv4Addr::from_str("192.168.0.55").unwrap(),
                    metric: 15_u32,
                }),
                RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                    afi: RipV2AddressFamily::Inet,
                    tag: 150_u16,
                    addr: Ipv4Addr::from_str("30.0.0.0").unwrap(),
                    mask: Ipv4Addr::from_str("255.128.0.0").unwrap().to_bits(),
                    nh: Ipv4Addr::from_str("192.168.0.55").unwrap(),
                    metric: 15_u32,
                }),
            ];

            let rte6_list = vec![
                RouteTableEntry::Ipv6Nexthop(Rte6Nexthop {
                    // "db8" nexthop
                    nh: Ipv6Addr::from_str("2001:db8:cafe::beef:face").unwrap(),
                    mbz1: 0_u16,
                    mbz2: 0_u8,
                    metric: RouteTableEntry::RIPNG_METRIC_NEXTHOP,
                }),
                RouteTableEntry::Ipv6Prefix(Rte6Prefix {
                    pfx: Ipv6Addr::from_str("2001:db8:cafe::dead:beef").unwrap(),
                    tag: 60_u16,
                    pfx_len: 64_u8,
                    metric: 9_u8,
                }),
                RouteTableEntry::Ipv6Nexthop(Rte6Nexthop {
                    // "db9" nexthop
                    nh: Ipv6Addr::from_str("2001:db9:cafe::beef:face").unwrap(),
                    mbz1: 0_u16,
                    mbz2: 0_u8,
                    metric: RouteTableEntry::RIPNG_METRIC_NEXTHOP,
                }),
                RouteTableEntry::Ipv6Prefix(Rte6Prefix {
                    pfx: Ipv6Addr::from_str("2001:db8:cafe::dead:beef").unwrap(),
                    tag: 60_u16,
                    pfx_len: 64_u8,
                    metric: 9_u8,
                }),
                RouteTableEntry::Ipv6Nexthop(Rte6Nexthop {
                    // unspecified nexthop
                    nh: Ipv6Addr::from_str("::").unwrap(),
                    mbz1: 0_u16,
                    mbz2: 0_u8,
                    metric: RouteTableEntry::RIPNG_METRIC_NEXTHOP,
                }),
                RouteTableEntry::Ipv6Prefix(Rte6Prefix {
                    pfx: Ipv6Addr::from_str("2001:db8:cafe::dead:beef").unwrap(),
                    tag: 60_u16,
                    pfx_len: 64_u8,
                    metric: 9_u8,
                }),
                RouteTableEntry::Ipv6Nexthop(Rte6Nexthop {
                    // unspecified nexthop
                    nh: Ipv6Addr::from_str("::").unwrap(),
                    mbz1: 0_u16,
                    mbz2: 0_u8,
                    metric: RouteTableEntry::RIPNG_METRIC_NEXTHOP,
                }),
                RouteTableEntry::Ipv6Prefix(Rte6Prefix {
                    pfx: Ipv6Addr::from_str("3fff::dead:beef").unwrap(),
                    tag: 60_u16,
                    pfx_len: 32_u8,
                    metric: 9_u8,
                }),
            ];

            rif.send_ripv2(&RipPacket::new(
                RipCommand::Request,
                &RipVersion::RIP,
                rte4_list.clone(),
            ));
            rif.send_ripv2(&RipPacket::new(
                RipCommand::Response,
                &RipVersion::RIP,
                rte4_list.clone(),
            ));

            rif.send_ripng(&RipPacket::new(
                RipCommand::Request,
                &RipVersion::RIPng,
                rte6_list.clone(),
            ));
            rif.send_ripng(&RipPacket::new(
                RipCommand::Response,
                &RipVersion::RIPng,
                rte6_list.clone(),
            ));
        }
        "listener" => std::thread::scope(|s| {
            let mut db = RipDb::new();
            let mut db_clone = db.clone();

            let mut rif = RipInterface::new(ifname).unwrap();
            let _ = rif.enable_ripv2();
            let _ = rif.enable_ripng();
            let ripv2_sock = rif.ripv2_sock.unwrap();
            let ripng_sock = rif.ripng_sock.unwrap();

            s.spawn(move || {
                listen_ripv2(&ripv2_sock, &mut db);
            });

            s.spawn(move || {
                listen_ripng(&ripng_sock, &mut db_clone);
            });
        }),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "Unsupported run mode",
            ));
        }
    }
    Ok(())
}
