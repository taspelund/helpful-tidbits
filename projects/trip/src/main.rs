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

enum RipVersion {
    RIPV2,
    RIPNG,
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
        RipVersion::RIPV2 => {
            let ripv2_sock = Socket::new(Domain::IPV4, Type::DGRAM, None)?;
            ripv2_sock.set_reuse_address(true)?;
            ripv2_sock.bind_device(Some(ifname.as_bytes()))?;
            ripv2_sock.bind(&SockAddr::from(RIPV2_BIND))?;
            ripv2_sock.set_multicast_all_v4(true)?;
            // ripv2_sock.set_multicast_if_v4(&V4_IFADDR)?;
            ripv2_sock.set_multicast_loop_v4(true)?;
            ripv2_sock
                .join_multicast_v4_n(&RIPV2_GROUP, &InterfaceIndexOrAddress::Index(ifindex))?;
            // for whatever reason, the socket doesn't rx packets sent to 224.0.0.9
            // if we call connect() against 224.0.0.9... so leave this unconnected for now.
            // ripv2_sock.connect(&SockAddr::from(RIPV2_DEST))?;
            Ok(ripv2_sock)
        }
        RipVersion::RIPNG => {
            let ripng_sock = Socket::new(Domain::IPV6, Type::DGRAM, None)?;
            ripng_sock.set_only_v6(true)?;
            ripng_sock.set_reuse_address(true)?;
            ripng_sock.bind_device(Some(ifname.as_bytes()))?;
            ripng_sock.bind(&SockAddr::from(RIPNG_BIND))?;
            ripng_sock.set_multicast_all_v6(true)?;
            // ripng_sock.set_multicast_if_v6(ifindex)?;
            ripng_sock.set_multicast_loop_v6(true)?;
            ripng_sock.join_multicast_v6(&RIPNG_GROUP, ifindex)?;
            // for whatever reason, the socket doesn't rx packets sent to ff02::9
            // if we call connect() against ff02::9... so leave this unconnected for now.
            // ripng_sock.connect(&SockAddr::from(RIPNG_DEST))?;
            Ok(ripng_sock)
        }
    }
}

fn main() -> std::io::Result<()> {
    let ifname = match env::args().nth(2) {
        Some(name) => name,
        None => {
            return Ok(eprintln!("ifname is a required argument"));
        }
    };
    match env::args().nth(1) {
        Some(mode) => match mode.as_str() {
            "sender" => {
                let message = "hello";

                let ripv2_tx = init_rip_sock(RipVersion::RIPV2, &ifname)?;
                // use send_to() instead of send() because the socket isn't connect()'d
                if let Ok(ripv2_bytes_sent) =
                    ripv2_tx.send_to(message.as_bytes(), &RIPV2_DEST.into())
                {
                    println!("IPv4 bytes sent: {}", ripv2_bytes_sent);
                }

                let ripng_tx = init_rip_sock(RipVersion::RIPNG, &ifname)?;
                // use send_to() instead of send() because the socket isn't connect()'d
                if let Ok(ripng_bytes_sent) =
                    ripng_tx.send_to(message.as_bytes(), &RIPNG_DEST.into())
                {
                    println!("IPv6 bytes sent: {}", ripng_bytes_sent);
                }
            }
            "listener" => {
                let ripv2_rx = init_rip_sock(RipVersion::RIPV2, &ifname)?;
                // convert from socket2 -> std::net to simplify our buffer implementation.
                // i.e. [MaybeUninit<u8>] seems more restrictive than [u8], so drop it.
                let ripv2_rx: UdpSocket = ripv2_rx.into();

                let mut ripv2_buf = [0u8; 4096];
                let ripv2_thread = std::thread::spawn(move || {
                    println!(
                        "listening on RIPv2 sock: {}, {:?}",
                        ripv2_rx.local_addr().unwrap(),
                        ripv2_rx.peer_addr()
                    );
                    loop {
                        if let Ok((rx_bytes, src_addr)) = ripv2_rx.recv_from(&mut ripv2_buf) {
                            if let Ok(msg) = std::str::from_utf8(&ripv2_buf) {
                                println!("{} bytes from {}: {}", rx_bytes, src_addr.ip(), msg);
                            } else {
                                eprintln!("failed to convert input to utf8 str!");
                            }
                        } else {
                            eprintln!("failed to read from listening socket!");
                        }
                        ripv2_buf = [0u8; 4096];
                    }
                });

                let ripng_rx: UdpSocket = init_rip_sock(RipVersion::RIPNG, &ifname)?.into();

                let mut ripng_buf = [0u8; 4096];
                let ripng_thread = std::thread::spawn(move || {
                    println!(
                        "listening on RIPNG sock: ({}, {:?})",
                        ripng_rx.local_addr().unwrap(),
                        ripng_rx.peer_addr()
                    );
                    loop {
                        if let Ok((rx_bytes, src_addr)) = ripng_rx.recv_from(&mut ripng_buf) {
                            if let Ok(msg) = std::str::from_utf8(&ripng_buf) {
                                println!("{} bytes from {}: {}", rx_bytes, src_addr.ip(), msg);
                            } else {
                                eprintln!("failed to convert input to utf8 str!");
                            }
                        } else {
                            eprintln!("failed to read from listening socket!");
                        }
                        ripng_buf = [0u8; 4096];
                    }
                });

                ripv2_thread.join().unwrap();
                ripng_thread.join().unwrap();
            }
            _ => {
                return Ok(eprintln!("unsupported run_mode"));
            }
        },
        None => {
            return Ok(eprintln!(
                "run_mode is a required argument: valid arguments (send, receive)"
            ));
        }
    }
    Ok(())
}
