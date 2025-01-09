use deku::{
    prelude::{DekuRead, DekuWrite},
    DekuContainerRead, DekuContainerWrite,
};
use socket2::{self, Domain, InterfaceIndexOrAddress, SockAddr, Socket, Type};
use std::{
    env,
    ffi::CString,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket},
};

const RIPV2_PORT: u16 = 520;
const RIPV2_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, RIPV2_PORT));
const RIPV2_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 9);
const RIPV2_DEST: SocketAddr = SocketAddr::V4(SocketAddrV4::new(RIPV2_GROUP, RIPV2_PORT));

const RIPNG_PORT: u16 = 521;
const RIPNG_BIND: SocketAddr =
    SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, RIPNG_PORT, 0, 0));
const RIPNG_GROUP: Ipv6Addr = Ipv6Addr::new(0xff02, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x9);
const RIPNG_DEST: SocketAddr = SocketAddr::V6(SocketAddrV6::new(RIPNG_GROUP, RIPNG_PORT, 0, 0));

// internal version indicator
enum ProtoVersion {
    RIPv2,
    RIPng,
}

const RIP_HEADER_LEN: usize = 4;
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  command (1)  |  version (1)  |       must be zero (2)        |
// +---------------+---------------+-------------------------------+
#[derive(Debug, DekuRead, DekuWrite)]
#[deku(endian = "big")]
struct RipHeader {
    cmd: u8,
    ver: u8,
    mbz: u16,
}

/// RIP message type
enum RipCommand {
    Request = 1,
    Response = 2,
}

/// RIP protocol version (in RIP header)
enum RipV2Version {
    RIPv1 = 1,
    RIPv2 = 2,
}

/// RIPng protocol version (in RIP header)
enum RipNgVersion {
    RIPng = 1,
}

/// RIPv2 Route Entry Types
enum RipV2Rte {
    Prefix(RipV2RtePrefix),
    Authentication(RipV2RtePrefix),
}

/// RIPv2 Address-Family Identifiers
enum RipV2AddressFamily {
    Inet = 0x0002,
    Auth = 0xFFFF,
}

const RIP_RTE_LEN: usize = 20;
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
/// RIPv2 Standard Route Entry: contains prefix.
struct RipV2RtePrefix {
    afi: u16,  // 2 bytes
    tag: u16,  // + 2 bytes = 4
    addr: u32, // + 4 bytes = 8
    mask: u32, // + 4 bytes = 12
    nh: u32,   // + 4 bytes = 16
    // u8 value encoded as u32
    metric: u32, // + 4 bytes = 20
}

/// RIPv2 Authentication Types
enum RipV2AuthType {
    Password = 0x0002,
}

//  0                   1                   2                   3 3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// | Command (1)   | Version (1)   |            unused             |
// +---------------+---------------+-------------------------------+
// |             0xFFFF            |    Authentication Type (2)    |
// +-------------------------------+-------------------------------+
// ~                       Authentication (16)                     ~
// +---------------------------------------------------------------+
/// RIPv2 Authentication Route Entry: contains auth instead of prefix, AFI = 0xFFFF
struct RipV2RteAuth {
    afi: u16,
    auth_type: u16,
    pw: [u8; 16],
}

/// RIPng Route Entry Types
enum RipNgRte {
    Prefix(RipNgRtePrefix),
    Nexthop(RipNgRteNexthop),
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                        IPv6 prefix (16)                       ~
// |                                                               |
// +---------------------------------------------------------------+
// |         route tag (2)         | prefix len (1)|  metric (1)   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// RIPng Standard Route Entry: contains prefix.
struct RipNgRtePrefix {
    pfx: [u8; 16],
    tag: u16,
    len: u8,
    met: u8,
}

//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// ~                    IPv6 next hop address (16)                 ~
// |                                                               |
// +---------------------------------------------------------------+
// |        must be zero (2)       |must be zero(1)|     0xFF      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// RIPng Standard Route Entry: contains next hop, metric = 0xFF
struct RipNgRteNexthop {
    nh: [u8; 16],
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

fn init_rip_sock(ver: ProtoVersion, ifname: &str) -> std::io::Result<Socket> {
    let ifindex = ifname_to_ifindex(ifname)?;
    match ver {
        ProtoVersion::RIPv2 => {
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
        ProtoVersion::RIPng => {
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

fn listen_rip_sock(ver: ProtoVersion, sock: &UdpSocket) {
    let mut buf = [0u8; 4096];
    println!(
        "listening for {} on {}",
        match ver {
            ProtoVersion::RIPv2 => "RIPv2",
            ProtoVersion::RIPng => "RIPng",
        },
        sock.local_addr().unwrap(),
    );
    loop {
        if let Ok((rx_bytes, src_addr)) = sock.recv_from(&mut buf) {
            if rx_bytes < RIP_HEADER_LEN {
                println!("data too short");
                println!(
                    "rx {} bytes from {} -> {:x?}",
                    rx_bytes,
                    src_addr.to_string(),
                    &buf[0..rx_bytes]
                );
                continue;
            }
            match RipHeader::from_bytes((&buf, 0)) {
                Ok((_remaining, rip_header)) => {
                    println!("rx rip pkt from {}: {:?}", src_addr.to_string(), rip_header)
                }
                Err(_e) => {
                    eprintln!("failed to parse rx bytes!");
                    break;
                }
            }
        } else {
            eprintln!("failed to read from listening socket!");
            break;
        }
        buf.fill(0);
    }
}

fn send_rip_sock(ver: ProtoVersion, sock: &UdpSocket, msg: &[u8]) {
    let dst = match ver {
        ProtoVersion::RIPv2 => &RIPV2_DEST,
        ProtoVersion::RIPng => &RIPNG_DEST,
    };
    // use send_to() instead of send() because the socket isn't connect()'d
    if let Ok(bytes_sent) = sock.send_to(msg, &dst) {
        println!(
            "{} bytes sent from {} to {}",
            bytes_sent,
            sock.local_addr().unwrap(),
            dst.to_string()
        );
    }
}

fn build_rip_header(ver: ProtoVersion, cmd: RipCommand) -> Vec<u8> {
    let rip_header = RipHeader {
        cmd: cmd as u8,
        ver: match ver {
            ProtoVersion::RIPv2 => RipV2Version::RIPv2 as u8,
            ProtoVersion::RIPng => RipNgVersion::RIPng as u8,
        },
        mbz: 0 as u16,
    };
    rip_header.to_bytes().unwrap()
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
                let message = match env::args().nth(3) {
                    Some(msg) => msg,
                    None => {
                        eprintln!("msg is a required argument for sender!");
                        eprintln!("{}", HELP);
                        return Ok(());
                    }
                };

                let ripv2_tx: UdpSocket = init_rip_sock(ProtoVersion::RIPv2, &ifname)?.into();
                let ripng_tx: UdpSocket = init_rip_sock(ProtoVersion::RIPng, &ifname)?.into();

                match message.as_str() {
                    "rip" => {
                        let buf = build_rip_header(ProtoVersion::RIPv2, RipCommand::Request);
                        send_rip_sock(ProtoVersion::RIPv2, &ripv2_tx, &buf);
                        let buf = build_rip_header(ProtoVersion::RIPv2, RipCommand::Response);
                        send_rip_sock(ProtoVersion::RIPv2, &ripv2_tx, &buf);
                        let buf = build_rip_header(ProtoVersion::RIPng, RipCommand::Request);
                        send_rip_sock(ProtoVersion::RIPng, &ripng_tx, &buf);
                        let buf = build_rip_header(ProtoVersion::RIPng, RipCommand::Response);
                        send_rip_sock(ProtoVersion::RIPng, &ripng_tx, &buf);
                    }
                    _ => {
                        let msg = &message.as_bytes();
                        send_rip_sock(ProtoVersion::RIPv2, &ripv2_tx, msg);
                        send_rip_sock(ProtoVersion::RIPng, &ripng_tx, msg);
                    }
                }
            }
            "listener" => {
                // convert from socket2 -> std::net to simplify our buffer implementation.
                // i.e. [MaybeUninit<u8>] seems more restrictive than [u8], so drop it.
                let ripv2_sock: UdpSocket = init_rip_sock(ProtoVersion::RIPv2, &ifname)?.into();
                let ripv2_thread = std::thread::spawn(move || {
                    listen_rip_sock(ProtoVersion::RIPv2, &ripv2_sock);
                });

                let ripng_sock: UdpSocket = init_rip_sock(ProtoVersion::RIPng, &ifname)?.into();
                let ripng_thread = std::thread::spawn(move || {
                    listen_rip_sock(ProtoVersion::RIPng, &ripng_sock);
                });

                ripv2_thread.join().unwrap();
                ripng_thread.join().unwrap();
            }
            _ => {
                return Ok(eprintln!("unsupported mode"));
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
