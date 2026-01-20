use crate::packet::{
    RipPacket, RipV2AddressFamily, RipV2AuthType, RipVersion, RouteTableEntry, Rte4Auth,
    Rte4Prefix, Rte6Nexthop, Rte6Prefix, RIPNG_PKT_MAX_LEN, RIP_HEADER_LEN, RIP_PKT_MAX_LEN,
};
use crate::types::RipRouter;
use slog::{info, Drain, Logger};
use std::{
    ffi::CString,
    net::{Ipv4Addr, Ipv6Addr, UdpSocket},
    str::FromStr,
    sync::{Arc, Mutex},
};

pub fn get_dummy_rte_lists() -> (Vec<RouteTableEntry>, Vec<RouteTableEntry>) {
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
        // prefix sent before nexthop, so rx'er should treat this as implicit nh (use src ip)
        RouteTableEntry::Ipv6Prefix(Rte6Prefix {
            pfx: Ipv6Addr::from_str("4001:db8:cafe::dead:beef").unwrap(),
            tag: 60_u16,
            pfx_len: 64_u8,
            metric: 9_u8,
        }),
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

    (rte4_list, rte6_list)
}

pub fn init_logger() -> Logger {
    let decorator = slog_term::TermDecorator::new().build();
    let drain = slog_term::FullFormat::new(decorator).build().fuse();
    let drain = slog_envlogger::new(drain).fuse();
    let drain = slog_async::Async::new(drain)
        .chan_size(0x2000)
        .build()
        .fuse();
    slog::Logger::root(drain, slog::o!())
}

pub fn ifname_to_ifindex(ifname: &str) -> Result<u32, std::ffi::NulError> {
    let ifindex = unsafe {
        let ifstr = CString::new(ifname)?.into_raw();
        let ifindex = libc::if_nametoindex(ifstr) as u32;
        drop(CString::from_raw(ifstr));
        ifindex
    };
    Ok(ifindex)
}

pub fn rip_listen(ver: RipVersion, sock: &UdpSocket, router: &Arc<Mutex<RipRouter>>) {
    let mut buf = [0u8; 4096];
    info!(
        router.lock().unwrap().log,
        "listening for {ver} on {}",
        sock.local_addr().unwrap(),
    );
    let max_len = match ver {
        RipVersion::RIPv2 => RIP_PKT_MAX_LEN,
        RipVersion::RIPng => RIPNG_PKT_MAX_LEN,
    };
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

            match RipPacket::from_bytes(ver, &buf[..rx_bytes]) {
                Ok(mut rip_pkt) => {
                    println!("rx rip pkt ({rx_bytes} bytes) from {src_addr}:\n{rip_pkt}\n");
                    rip_pkt.process(router, src_addr.ip());
                    match ver {
                        RipVersion::RIPv2 => {
                            println!("{ver} RIB: {:#?}\n", router.lock().unwrap().db4());
                        }
                        RipVersion::RIPng => {
                            println!("{ver} RIB: {:#?}\n", router.lock().unwrap().db6());
                        }
                    }
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
