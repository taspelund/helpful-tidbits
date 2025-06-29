use crate::types::{RipPathInfo, RipRouter};
use byteorder::{BigEndian, ReadBytesExt};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::{
    fmt::Debug,
    io::Cursor,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
    sync::{Arc, Mutex},
};

/// Constants for `RIPv2` sockets
pub const RIPV2_PORT: u16 = 520;
pub const RIPV2_BIND: SocketAddr =
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RIPV2_PORT));
pub const RIPV2_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
pub const RIPV2_DEST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(RIPV2_GROUP, RIPV2_PORT));
/// Constants for `RIPng` sockets
pub const RIPNG_PORT: u16 = 521;
pub const RIPNG_BIND: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, RIPNG_PORT, 0, 0));
pub const RIPNG_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9);
pub const RIPNG_DEST: SocketAddr = SocketAddr::V6(SocketAddrV6::new(RIPNG_GROUP, RIPNG_PORT, 0, 0));
/// Constants for header lengths and packet sizes
// XXX: query link MTU from kernel
pub const ASSUMED_MTU: usize = 1500;
pub const IPV4_HEADER_LEN: usize = 20;
pub const IPV6_HEADER_LEN: usize = 40;
pub const UDP_HEADER_LEN: usize = 8;
pub const RIP_HEADER_LEN: usize = 4;
pub const RIP_PKT_MAX_LEN: usize = ASSUMED_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN;
// const RIP_PKT_MAX_RTE: usize = RIP_PKT_MAX_LEN / RouteTableEntry::SIZE;
pub const RIPNG_PKT_MAX_LEN: usize =
    ASSUMED_MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN;
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
pub struct RipPacket {
    cmd: RipCommand, // header start
    ver: RipVersion,
    mbz: u16,
    rt_entries: Vec<RouteTableEntry>, // payload start
}

impl RipPacket {
    pub const INFINITY_METRIC: u8 = 16;

    pub fn version(&self) -> RipVersion {
        self.ver
    }

    pub fn new(cmd: RipCommand, ver: RipVersion, rt_entries: Vec<RouteTableEntry>) -> RipPacket {
        Self {
            cmd,
            ver,
            mbz: 0u16,
            rt_entries,
        }
    }

    pub fn from_bytes(proto: RipVersion, b: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(b);

        // START HEADER
        let c = cursor.read_u8()?;
        let Some(cmd) = RipCommand::from_u8(c) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported RIP command: {c}"),
            ));
        };

        let v = cursor.read_u8()?;
        let Some(ver) = RipVersion::from_u8(proto, v) else {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid RIP version. Expected ({}), Received ({v})",
                    proto.to_u8()
                ),
            ));
        };

        let mbz = cursor.read_u16::<BigEndian>()?;
        if mbz != 0 {
            // RFCs 2453 (RIPv2) and 2080 (RIPng) don't state what to do here.
            // It seems sane to log this and otherwise ignore it.
            eprintln!("must-be-zero field is not set to zero: {mbz}");
        } // END HEADER

        let total_len = b.len();
        let header_len = usize::try_from(cursor.position()).unwrap();
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
            let start = usize::try_from(cursor.position()).unwrap();
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

    pub fn to_byte_vec(&self) -> Vec<u8> {
        let mut b = Vec::<u8>::new();
        b.push(self.cmd.to_u8()); // single byte, no order
        b.push(self.ver.to_u8()); // single byte, no order
        b.extend_from_slice(&self.mbz.to_be_bytes());
        for rte in &self.rt_entries {
            b.extend_from_slice(&rte.to_bytes());
        }
        b
    }

    pub fn process(&mut self, router: &Arc<Mutex<RipRouter>>, src: IpAddr) {
        let mut nh: Option<Ipv6Addr> = None;
        for rte in &mut self.rt_entries {
            match rte {
                RouteTableEntry::Ipv4Prefix(prefix4) => {
                    let metric = u8::try_from(prefix4.metric).unwrap();
                    let rpi = RipPathInfo::new(
                        if prefix4.nh.is_unspecified() {
                            src
                        } else {
                            IpAddr::V4(prefix4.nh)
                        },
                        0u32,
                        metric,
                        prefix4.tag,
                    );
                    match metric {
                        RipPacket::INFINITY_METRIC => router
                            .lock()
                            .unwrap()
                            .remove_prefix_path(IpNet::from(prefix4.prefix()), &rpi),
                        _ => router
                            .lock()
                            .unwrap()
                            .insert_prefix_path(IpNet::from(prefix4.prefix()), &rpi),
                    }
                }
                RouteTableEntry::Ipv4Authentication(auth4) => {
                    // XXX: set auth here (need access to rif.set_auth_pw())
                    println!("{auth4:?}");
                }
                RouteTableEntry::Ipv6Prefix(prefix6) => {
                    let rpi = RipPathInfo::new(
                        match nh {
                            None => src,
                            Some(n) => {
                                if n.is_unspecified() {
                                    src
                                } else {
                                    IpAddr::V6(n)
                                }
                            }
                        },
                        0u32,
                        prefix6.metric,
                        prefix6.tag,
                    );
                    match prefix6.metric {
                        RipPacket::INFINITY_METRIC => router
                            .lock()
                            .unwrap()
                            .remove_prefix_path(IpNet::from(prefix6.prefix()), &rpi),
                        _ => router
                            .lock()
                            .unwrap()
                            .insert_prefix_path(IpNet::from(prefix6.prefix()), &rpi),
                    }
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
            self.ver.to_u8(),
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RipCommand {
    Request = 1,
    Response = 2,
}

impl RipCommand {
    fn to_u8(self) -> u8 {
        self as u8
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
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RipVersion {
    RIPv2 = 2,
    RIPng = 1,
}

impl std::fmt::Display for RipVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            match self {
                Self::RIPv2 => "RIPv2",
                Self::RIPng => "RIPng",
            }
        )
    }
}

impl RipVersion {
    fn to_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(ver: RipVersion, v: u8) -> Option<Self> {
        if v == ver.to_u8() {
            Some(ver)
        } else {
            None
        }
    }
}

/// `RIPv2` Address-Family Identifiers
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RipV2AddressFamily {
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

    fn to_u16(self) -> u16 {
        match self {
            Self::Inet => 0x0002,
            Self::Auth => 0xFFFF,
        }
    }
}

/// `RIPv2` Authentication Types
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RipV2AuthType {
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

    fn to_u16(self) -> u16 {
        self as u16
    }
}

/// Route Table Entry Types
#[derive(Clone, Debug)]
pub enum RouteTableEntry {
    // XXX: remove a layer of enum nesting here?
    Ipv4Prefix(Rte4Prefix),
    Ipv4Authentication(Rte4Auth),
    Ipv6Prefix(Rte6Prefix),
    Ipv6Nexthop(Rte6Nexthop),
}

impl RouteTableEntry {
    // All RTEs are the same length, across all RTE types & RIP Protocol versions
    pub const SIZE: usize = 20;
    // RIPNg RTE with metric == 0xFF carries a nexthop
    pub const RIPNG_METRIC_NEXTHOP: u8 = u8::MAX;

    fn from_bytes(ver: RipVersion, b: &[u8]) -> std::io::Result<Self> {
        match ver {
            RipVersion::RIPv2 => {
                let mut cursor = Cursor::new(b);
                let af = cursor.read_u16::<BigEndian>()?;
                match RipV2AddressFamily::from_u16(af) {
                    Some(afi) => match afi {
                        RipV2AddressFamily::Inet => {
                            Ok(RouteTableEntry::Ipv4Prefix(Rte4Prefix::parse(&mut cursor)?))
                        }
                        RipV2AddressFamily::Auth => Ok(RouteTableEntry::Ipv4Authentication(
                            Rte4Auth::parse(&mut cursor)?,
                        )),
                    },
                    None => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unsupported RIPv2 Address Family: {af}"),
                    )),
                }
            }
            RipVersion::RIPng => {
                let mut cursor = Cursor::new(b);
                let pfx = Ipv6Addr::from_bits(cursor.read_u128::<BigEndian>()?);
                let tag = cursor.read_u16::<BigEndian>()?;
                let pfx_len = cursor.read_u8()?;
                let metric = cursor.read_u8()?;

                match metric {
                    RouteTableEntry::RIPNG_METRIC_NEXTHOP => Ok(RouteTableEntry::Ipv6Nexthop(
                        Rte6Nexthop::from_parts(pfx, tag, pfx_len, metric)?,
                    )),
                    // RTE with a valid metric carries a prefix
                    0..=RipPacket::INFINITY_METRIC => Ok(RouteTableEntry::Ipv6Prefix(
                        Rte6Prefix::from_parts(pfx, tag, pfx_len, metric)?,
                    )),
                    _ => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "Invalid metric {metric}: cannot be greater than infinity ({})",
                            RipPacket::INFINITY_METRIC
                        ),
                    )),
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
pub struct Rte4Prefix {
    pub afi: RipV2AddressFamily, // 2 bytes
    pub tag: u16,                // + 2 bytes = 4
    pub addr: Ipv4Addr,          // + 4 bytes = 8
    pub mask: u32,               // + 4 bytes = 12
    pub nh: Ipv4Addr,            // + 4 bytes = 16
    // u8 value encoded as u32
    pub metric: u32, // + 4 bytes = 20
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

    fn parse(cursor: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
        let tag = cursor.read_u16::<BigEndian>()?;
        let addr = Ipv4Addr::from_bits(cursor.read_u32::<BigEndian>()?);
        let mask = cursor.read_u32::<BigEndian>()?;
        let nh = Ipv4Addr::from_bits(cursor.read_u32::<BigEndian>()?);
        let metric = cursor.read_u32::<BigEndian>()?;

        if addr.is_loopback() || addr.is_multicast() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Prefix {addr}: cannot be multicast or loopback range"),
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
                format!("Invalid Nexthop {nh}: cannot be multicast or loopback address"),
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

        Ok(Rte4Prefix {
            afi: RipV2AddressFamily::Inet,
            tag,
            addr,
            mask,
            nh,
            metric,
        })
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
pub struct Rte4Auth {
    pub afi: RipV2AddressFamily,
    pub auth_type: RipV2AuthType,
    pub pw: u128,
}

impl Rte4Auth {
    fn parse(cursor: &mut Cursor<&[u8]>) -> std::io::Result<Self> {
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

        Ok(Rte4Auth {
            afi: RipV2AddressFamily::Auth,
            auth_type,
            pw,
        })
    }
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
pub struct Rte6Prefix {
    pub pfx: Ipv6Addr,
    pub tag: u16,
    pub pfx_len: u8,
    pub metric: u8,
}

impl Rte6Prefix {
    fn prefix(&self) -> Ipv6Net {
        Ipv6Net::new_assert(self.pfx, self.pfx_len).trunc()
    }

    fn from_parts(pfx: Ipv6Addr, tag: u16, pfx_len: u8, metric: u8) -> std::io::Result<Self> {
        if pfx.is_multicast() || pfx.is_loopback() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Prefix {pfx}: cannot be multicast or loopback range"),
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

        Ok(Self {
            pfx,
            tag,
            pfx_len,
            metric,
        })
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
pub struct Rte6Nexthop {
    pub nh: Ipv6Addr,
    pub mbz1: u16,
    pub mbz2: u8,
    pub metric: u8, // always set to u8::MAX
}

impl Rte6Nexthop {
    fn from_parts(nh: Ipv6Addr, mbz1: u16, mbz2: u8, metric: u8) -> std::io::Result<Self> {
        if nh.is_multicast() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("Invalid Nexthop ({nh}): must be unicast"),
            ));
        }

        if mbz1 != 0 {
            eprintln!("2-byte must-be-zero field is not set to zero: {mbz1}");
        }

        if mbz2 != 0 {
            eprintln!("1-byte must-be-zero field is not set to zero: {mbz2}");
        }

        Ok(Self {
            nh,
            mbz1,
            mbz2,
            metric,
        })
    }
}
