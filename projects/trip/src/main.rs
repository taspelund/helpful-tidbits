use byteorder::{BigEndian, ReadBytesExt};
use socket2::{self, Domain, InterfaceIndexOrAddress, SockAddr, Socket, Type};
use std::{
    env,
    ffi::CString,
    io::Cursor,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
    str::FromStr,
};

/// Constants for RIPv2 sockets
const RIPV2_PORT: u16 = 520;
const RIPV2_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RIPV2_PORT));
const RIPV2_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
const RIPV2_DEST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(RIPV2_GROUP, RIPV2_PORT));
/// Constants for RIPng sockets
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
const RIP_PKT_MAX_LEN: usize =
    (ASSUMED_MTU - IPV4_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN) / RouteTableEntry::SIZE;
const RIPNG_PKT_MAX_LEN: usize =
    (ASSUMED_MTU - IPV6_HEADER_LEN - UDP_HEADER_LEN - RIP_HEADER_LEN) / RouteTableEntry::SIZE;

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  command (1)  |  version (1)  |       must be zero (2)        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                Route Table Entry 1 (20)                       ~
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                         ...                                   ~
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                Route Table Entry N (20)                       ~
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Debug)]
struct RipPacket {
    // XXX: go back to struct RipHeader
    cmd: u8, // header start
    ver: u8,
    mbz: u16,
    rt_entries: Vec<RouteTableEntry>, // payload start
}

impl RipPacket {
    fn new(cmd: RipCommand, proto: &RipVersion, rt_entries: Vec<RouteTableEntry>) -> RipPacket {
        Self {
            cmd: cmd as u8,
            ver: proto.to_u8(),
            mbz: 0u16,
            rt_entries,
        }
    }

    fn from_bytes(proto: &RipVersion, b: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(b);

        let cmd = cursor.read_u8()?; // START HEADER
        if cmd != RipCommand::Request.to_u8() && cmd != RipCommand::Response.to_u8() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("Unsupported RIP command: {}", cmd),
            ));
        }

        let ver = cursor.read_u8()?;
        if ver != proto.to_u8() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid RIP version. Expected ({}), Received ({})",
                    proto.to_u8(),
                    ver
                ),
            ));
        }

        let mbz = cursor.read_u16::<BigEndian>()?;
        if mbz != 0 {
            // RFCs 2453 (RIPv2) and 2080 (RIPng) don't state what to do here.
            // It seems sane to log this and otherwise ignore it.
            eprintln!("must-be-zero field is not set to zero: {}", mbz);
        } // END HEADER

        let total_len = b.len();
        let header_len = cursor.position() as usize;
        let payload_len = total_len - header_len;
        if payload_len % RouteTableEntry::SIZE != 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!(
                    "Invalid payload length. Payload must be a multiple of {}, found {}",
                    RouteTableEntry::SIZE,
                    payload_len
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
        b.push(self.cmd); // single byte, no order
        b.push(self.ver); // single byte, no order
        b.extend_from_slice(&self.mbz.to_be_bytes());
        for rte in &self.rt_entries {
            b.extend(rte.to_byte_vec());
        }
        b
    }
}

impl std::fmt::Display for RipPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let cmd_str = match self.cmd {
            1 => Some("Request"),
            2 => Some("Response"),
            _ => None,
        };
        write!(
            f,
            "RipPacket {{\n\tcmd: {},\n\tver: 0x{:x},\n\tmbz: 0x{:x},\n\trt_entries: (\n{}\n\t)\n}}",
            match cmd_str {
                Some(s) => s.to_string(),
                None => self.cmd.to_string(),
            },
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
#[derive(Clone, PartialEq, Eq)]
enum RipCommand {
    Request = 1,
    Response = 2,
}

impl RipCommand {
    fn to_u8(&self) -> u8 {
        self.clone() as u8
    }
}

/// RIP/RIPng version numbers
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

/// RIPv2 Address-Family Identifiers
#[derive(PartialEq, Eq)]
enum RipV2AddressFamily {
    Inet = 0x0002,
    Auth = 0xFFFF,
    Unsupported,
}

impl RipV2AddressFamily {
    fn from_u16(n: u16) -> Self {
        match n {
            0x0002 => Self::Inet,
            0xFFFF => Self::Auth,
            _ => Self::Unsupported,
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            Self::Inet => 0x0002,
            Self::Auth => 0xFFFF,
            Self::Unsupported => 0x0,
        }
    }
}

/// RIPv2 Authentication Types
#[derive(PartialEq, Eq)]
enum RipV2AuthType {
    Password = 0x0002,
    Unsupported,
}

impl RipV2AuthType {
    fn from_u16(n: u16) -> Self {
        match n {
            0x0002 => Self::Password,
            _ => Self::Unsupported,
        }
    }

    fn to_u16(&self) -> u16 {
        match self {
            Self::Password => 0x0002,
            Self::Unsupported => 0x0,
        }
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
    // All RTEs are the same length, across all RTE types & Protocol versions
    const SIZE: usize = 20;

    fn from_bytes(ver: &RipVersion, b: &[u8]) -> std::io::Result<Self> {
        let mut cursor = Cursor::new(b);
        match ver {
            RipVersion::RIP => {
                let afi = cursor.read_u16::<BigEndian>()?;
                match RipV2AddressFamily::from_u16(afi) {
                    RipV2AddressFamily::Inet => {
                        let tag = cursor.read_u16::<BigEndian>()?;
                        // XXX: add sanity check for valid unicast prefix
                        let addr = cursor.read_u32::<BigEndian>()?;
                        let mask = cursor.read_u32::<BigEndian>()?;
                        // XXX: add sanity check for valid unicast nh
                        let nh = cursor.read_u32::<BigEndian>()?;
                        // XXX: add sanity check for max RIP metric (16)
                        let metric = cursor.read_u32::<BigEndian>()?;
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
                        // XXX: check for supported auth type
                        let auth_type = cursor.read_u16::<BigEndian>()?;
                        if RipV2AuthType::from_u16(auth_type) == RipV2AuthType::Unsupported {
                            return Err(std::io::Error::new(
                                std::io::ErrorKind::InvalidData,
                                format!("Unsupported RIPv2 Authentication Type: {}", auth_type),
                            ));
                        }
                        let pw = cursor.read_u128::<BigEndian>()?;
                        Ok(Self::Ipv4Authentication(Rte4Auth { afi, auth_type, pw }))
                    }
                    RipV2AddressFamily::Unsupported => Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!("Unsupported RIPv2 Address Family: {}", afi),
                    )),
                }
            }
            RipVersion::RIPng => {
                // XXX: add sanity check for valid unicast prefix/nh
                let addr = cursor.read_u128::<BigEndian>()?;
                let tag = cursor.read_u16::<BigEndian>()?;
                let plen = cursor.read_u8()?;
                // XXX: add sanity check for max RIP metric (16)
                let metric = cursor.read_u8()?;
                match metric {
                    // Metric is always 0xFF for Nexthop
                    u8::MAX => Ok(Self::Ipv6Nexthop(Rte6Nexthop {
                        nh: addr,
                        mbz1: tag,
                        mbz2: plen,
                        metric,
                    })),
                    _ => Ok(Self::Ipv6Prefix(Rte6Prefix {
                        pfx: addr,
                        tag,
                        pfx_len: plen,
                        metric,
                    })),
                }
            }
        }
    }

    fn to_byte_vec(&self) -> Vec<u8> {
        match self {
            Self::Ipv4Prefix(prefix4) => {
                let mut b = Vec::<u8>::new();
                b.extend_from_slice(&prefix4.afi.to_be_bytes());
                b.extend_from_slice(&prefix4.tag.to_be_bytes());
                b.extend_from_slice(&prefix4.addr.to_be_bytes());
                b.extend_from_slice(&prefix4.mask.to_be_bytes());
                b.extend_from_slice(&prefix4.nh.to_be_bytes());
                b.extend_from_slice(&prefix4.metric.to_be_bytes());
                b
            }
            Self::Ipv4Authentication(auth4) => {
                let mut b = Vec::<u8>::new();
                b.extend_from_slice(&auth4.afi.to_be_bytes());
                b.extend_from_slice(&auth4.auth_type.to_be_bytes());
                b.extend_from_slice(&auth4.pw.to_be_bytes());
                b
            }
            Self::Ipv6Prefix(prefix6) => {
                let mut b = Vec::<u8>::new();
                b.extend_from_slice(&prefix6.pfx.to_be_bytes());
                b.extend_from_slice(&prefix6.tag.to_be_bytes());
                b.extend_from_slice(&prefix6.pfx_len.to_be_bytes());
                b.extend_from_slice(&prefix6.metric.to_be_bytes());
                b
            }
            Self::Ipv6Nexthop(nexthop6) => {
                let mut b = Vec::<u8>::new();
                b.extend_from_slice(&nexthop6.nh.to_be_bytes());
                b.extend_from_slice(&nexthop6.mbz1.to_be_bytes());
                b.extend_from_slice(&nexthop6.mbz2.to_be_bytes());
                b.extend_from_slice(&nexthop6.metric.to_be_bytes());
                b
            }
        }
    }
}

impl std::fmt::Display for RouteTableEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouteTableEntry::Ipv4Prefix(prefix4) => {
                let afi_str = match prefix4.afi {
                    0x0002 => Some("AF_INET"),
                    0xFFFF => Some("AF_AUTH"),
                    _ => None,
                };
                write!(
                    f,
                    "Rte4Prefix {{ afi: {}, tag: {}, addr: {}, mask: {}, nh: {}, metric: {} }}",
                    match afi_str {
                        Some(s) => s.to_string(),
                        None => prefix4.afi.to_string(),
                    },
                    prefix4.tag,
                    Ipv4Addr::from_bits(prefix4.addr),
                    Ipv4Addr::from_bits(prefix4.mask),
                    Ipv4Addr::from_bits(prefix4.nh),
                    prefix4.metric
                )
            }
            RouteTableEntry::Ipv4Authentication(auth4) => {
                // XXX: impl RipV2AddressFamily::try_from<u16> for this?
                let afi_str = match auth4.afi {
                    0x0002 => Some("AF_INET"),
                    0xFFFF => Some("AF_AUTH"),
                    _ => None,
                };
                write!(
                    f,
                    "Rte4Auth {{ afi: {}, auth_type: {}, pw: {:x?} }}",
                    match afi_str {
                        Some(s) => s.to_string(),
                        None => auth4.afi.to_string(),
                    },
                    auth4.auth_type,
                    auth4.pw.to_be_bytes(),
                )
            }
            RouteTableEntry::Ipv6Prefix(prefix6) => {
                write!(
                    f,
                    "Rte6Prefix {{ pfx: {:x?}, tag: {}, pfx_len: {}, metric: {} }}",
                    Ipv6Addr::from_bits(prefix6.pfx),
                    prefix6.tag,
                    prefix6.pfx_len,
                    prefix6.metric
                )
            }
            RouteTableEntry::Ipv6Nexthop(nexthop6) => {
                write!(
                    f,
                    "Rte6Nexthop {{ nh: {:x?}, mbz1: {}, mbz2: {}, metric: {} }}",
                    Ipv6Addr::from_bits(nexthop6.nh),
                    nexthop6.mbz1,
                    nexthop6.mbz2,
                    nexthop6.metric,
                )
            }
        }
    }
}

/// RIPv2 Standard Route Entry: contains prefix.
//  0                   1                   2                   3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Address Family Identifier (2) |        Route Tag (2)          |
// +-------------------------------+-------------------------------+
// |                         IP Address (4)                        |
// +---------------------------------------------------------------+
// |                         Subnet Mask (4)                       |
// +---------------------------------------------------------------+
// |                         Next Hop (4)                          |
// +---------------------------------------------------------------+
// |                         Metric (4)                            |
// +---------------------------------------------------------------+
#[derive(Clone, Debug)]
struct Rte4Prefix {
    afi: u16,  // 2 bytes
    tag: u16,  // + 2 bytes = 4
    addr: u32, // + 4 bytes = 8
    mask: u32, // + 4 bytes = 12
    nh: u32,   // + 4 bytes = 16
    // u8 value encoded as u32
    metric: u32, // + 4 bytes = 20
}

/// RIPv2 Authentication Route Entry: contains auth instead of prefix, AFI = 0xFFFF
//  0                   1                   2                   3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Command (1)   | Version (1)   |            unused             |
// +---------------+---------------+-------------------------------+
// |             0xFFFF            |    Authentication Type (2)    |
// +-------------------------------+-------------------------------+
// ~                       Authentication (16)                     ~
// +---------------------------------------------------------------+
#[derive(Clone, Debug)]
struct Rte4Auth {
    afi: u16,
    auth_type: u16,
    pw: u128,
}

/// RIPng Standard Route Entry: contains prefix.
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                        IPv6 prefix (16)                       ~
// |                                                               |
// +---------------------------------------------------------------+
// |         route tag (2)         | prefix len (1)|  metric (1)   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug)]
struct Rte6Prefix {
    pfx: u128,
    tag: u16,
    pfx_len: u8,
    metric: u8,
}

/// RIPng Standard Route Entry: contains next hop, metric = 0xFF
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                    IPv6 next hop address (16)                 ~
// |                                                               |
// +---------------------------------------------------------------+
// |        must be zero (2)       |must be zero(1)|     0xFF      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#[derive(Clone, Debug)]
struct Rte6Nexthop {
    nh: u128,
    mbz1: u16,
    mbz2: u8,
    metric: u8, // always set to u8::MAX
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

fn init_rip_sock(ver: RipVersion, ifname: &str) -> std::io::Result<Socket> {
    let ifindex = ifname_to_ifindex(ifname)?;
    match ver {
        RipVersion::RIP => {
            let ripv2_sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
            ripv2_sock.set_reuse_address(true)?;
            ripv2_sock.bind_device(Some(ifname.as_bytes()))?;
            ripv2_sock.bind(&SockAddr::from(RIPV2_BIND))?;
            ripv2_sock.set_multicast_all_v4(true)?;
            // ripv2_sock.set_multicast_if_v4(&V4_IFADDR)?;
            // XXX: we may want to disable this at some point
            ripv2_sock.set_multicast_loop_v4(true)?;
            ripv2_sock
                .join_multicast_v4_n(&RIPV2_GROUP, &InterfaceIndexOrAddress::Index(ifindex))?;
            // for whatever reason, the socket doesn't rx packets sent to 224.0.0.9
            // if we call connect() against 224.0.0.9... so leave this unconnected for now?
            // ripv2_sock.connect(&SockAddr::from(RIPV2_DEST))?;
            Ok(ripv2_sock)
        }
        RipVersion::RIPng => {
            let ripng_sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
            ripng_sock.set_only_v6(true)?;
            ripng_sock.set_reuse_address(true)?;
            ripng_sock.bind_device(Some(ifname.as_bytes()))?;
            ripng_sock.bind(&SockAddr::from(RIPNG_BIND))?;
            ripng_sock.set_multicast_all_v6(true)?;
            // ripng_sock.set_multicast_if_v6(ifindex)?;
            // XXX: we may want to disable this at some point
            ripng_sock.set_multicast_loop_v6(true)?;
            ripng_sock.join_multicast_v6(&RIPNG_GROUP, ifindex)?;
            // for whatever reason, the socket doesn't rx packets sent to ff02::9
            // if we call connect() against ff02::9... so leave this unconnected for now?
            // ripng_sock.connect(&SockAddr::from(RIPNG_DEST))?;
            Ok(ripng_sock)
        }
    }
}

fn listen_rip_sock(proto: &RipVersion, sock: &UdpSocket) {
    let mut buf = [0u8; 4096];
    println!(
        "listening for {} on {}",
        match proto {
            RipVersion::RIP => "RIPv2",
            RipVersion::RIPng => "RIPng",
        },
        sock.local_addr().unwrap(),
    );
    let max_len = match proto {
        RipVersion::RIP => RIP_PKT_MAX_LEN,
        RipVersion::RIPng => RIPNG_PKT_MAX_LEN,
    };
    loop {
        buf.fill(0);
        if let Ok((rx_bytes, src_addr)) = sock.recv_from(&mut buf) {
            println!(
                "rx {} bytes from {} -> {:x?}",
                rx_bytes,
                src_addr,
                &buf[0..rx_bytes]
            );

            if rx_bytes < RIP_HEADER_LEN {
                println!("data too short");
                continue;
            }

            // XXX: set buf len to RIP_PKT_MAX_LEN to enforce upper bounds?
            if rx_bytes > max_len {
                println!("data too large");
                continue;
            }

            match RipPacket::from_bytes(proto, &buf[..rx_bytes]) {
                Ok(rip_pkt) => {
                    println!(
                        "rx rip pkt ({} bytes) from {}:\n{}\n",
                        rx_bytes, src_addr, rip_pkt
                    )
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

fn send_rip_sock(ver: &RipVersion, sock: &UdpSocket, rp: RipPacket) {
    let dst = match ver {
        RipVersion::RIP => &RIPV2_DEST,
        RipVersion::RIPng => &RIPNG_DEST,
    };
    // use send_to() instead of send() because the socket isn't connect()'d
    if let Ok(bytes_sent) = sock.send_to(&rp.to_byte_vec(), dst) {
        println!(
            "tx rip pkt ({} bytes) from {} to {}:\n{}\n",
            bytes_sent,
            sock.local_addr().unwrap(),
            dst,
            rp
        );
    }
}

const HELP: &str = "trip {sender <ifname> <msg> | listener <ifname>}";

fn main() -> std::io::Result<()> {
    let ifname = match env::args().nth(2) {
        Some(name) => name,
        None => {
            eprintln!("ifname is a required argument!");
            eprintln!("{}", HELP);
            return Ok(());
        }
    };

    match env::args().nth(1) {
        Some(mode) => match mode.as_str() {
            "sender" => {
                let ripv2_tx: UdpSocket = init_rip_sock(RipVersion::RIP, &ifname)?.into();
                let ripv2_proto = RipVersion::RIP;
                let ripng_tx: UdpSocket = init_rip_sock(RipVersion::RIPng, &ifname)?.into();
                let ripng_proto = RipVersion::RIPng;

                let rte4_list = vec![
                    RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                        afi: RipV2AddressFamily::Inet as u16,
                        tag: 50_u16,
                        addr: Ipv4Addr::from_str("10.0.0.0").unwrap().to_bits(),
                        mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                        nh: Ipv4Addr::from_str("192.168.0.1").unwrap().to_bits(),
                        metric: 5_u32,
                    }),
                    RouteTableEntry::Ipv4Authentication(Rte4Auth {
                        afi: RipV2AddressFamily::Auth.to_u16(),
                        auth_type: RipV2AuthType::Password.to_u16(),
                        pw: 0u128,
                    }),
                ];
                let rte6_list = vec![
                    RouteTableEntry::Ipv6Nexthop(Rte6Nexthop {
                        nh: Ipv6Addr::from_str("2001:db8:cafe::beef:face")
                            .unwrap()
                            .to_bits(),
                        mbz1: 0_u16,
                        mbz2: 0_u8,
                        metric: 12_u8,
                    }),
                    RouteTableEntry::Ipv6Prefix(Rte6Prefix {
                        pfx: Ipv6Addr::from_str("2001:db8:cafe::dead:beef")
                            .unwrap()
                            .to_bits(),
                        tag: 60_u16,
                        pfx_len: 64_u8,
                        metric: 9_u8,
                    }),
                ];

                let rp = RipPacket::new(RipCommand::Request, &ripv2_proto, rte4_list.clone());
                send_rip_sock(&ripv2_proto, &ripv2_tx, rp);
                let rp = RipPacket::new(RipCommand::Response, &ripv2_proto, rte4_list.clone());
                send_rip_sock(&ripv2_proto, &ripv2_tx, rp);

                let rp = RipPacket::new(RipCommand::Request, &ripng_proto, rte6_list.clone());
                send_rip_sock(&ripng_proto, &ripng_tx, rp);
                let rp = RipPacket::new(RipCommand::Response, &ripng_proto, rte6_list.clone());
                send_rip_sock(&ripng_proto, &ripng_tx, rp);
            }
            "listener" => {
                // convert from socket2 -> std::net to simplify our buffer implementation.
                // i.e. [MaybeUninit<u8>] seems more restrictive than [u8], so drop it.
                let ripv2_proto = RipVersion::RIP;
                let ripv2_sock: UdpSocket = init_rip_sock(RipVersion::RIP, &ifname)?.into();
                let ripv2_thread = std::thread::spawn(move || {
                    listen_rip_sock(&ripv2_proto, &ripv2_sock);
                });

                let ripng_proto = RipVersion::RIPng;
                let ripng_sock: UdpSocket = init_rip_sock(RipVersion::RIPng, &ifname)?.into();
                let ripng_thread = std::thread::spawn(move || {
                    listen_rip_sock(&ripng_proto, &ripng_sock);
                });

                ripv2_thread.join().unwrap();
                ripng_thread.join().unwrap();
            }
            _ => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "Unsupported run mode",
                ));
            }
        },
        None => {
            eprintln!("run mode is a required argument!");
            eprintln!("{}", HELP);
            return Ok(());
        }
    }
    Ok(())
}
