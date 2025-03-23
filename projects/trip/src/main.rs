use crate::helpers::*;
use crate::packet::*;
use crate::types::*;
use std::thread::sleep;
use std::time::Duration;
use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
    sync::{Arc, Mutex},
};

mod helpers;
mod packet;
mod types;

// XXX: Implement global state, i.e. a `struct rip {}`
//      (this is technically done... but I'm 100% positive this needs cleaned up)
// XXX: Move all the rte{4,6}_list stuff into a test module
// XXX: Implement proper program structure, i.e. main() should call some init functions for things like `struct rip` and then launch an event loop
// XXX: Implement some kind of CLI (not sure if this will interact w/ daemon via UDS, dropshot, or something else entirely)
// XXX: Implement CLI args for providing a pidfile-type interface for an instance of tripd (so multiple instances can run in parallel, e.g. in different netns')
// XXX: Use real errors instead of piggy-backing on std::io::Result

const HELP: &str = "trip {sender | listener} <ifname>";

fn main() -> std::io::Result<()> {
    let Some(mode) = env::args().nth(1) else {
        eprintln!("run-mode is a required argument!");
        eprintln!("{HELP}");
        return Ok(());
    };

    let Some(ifname) = env::args().nth(2) else {
        eprintln!("ifname is a required argument!");
        eprintln!("{HELP}");
        return Ok(());
    };

    match mode.as_str() {
        "sender" => {
            let rip = Arc::new(Mutex::new(Rip::new()));

            let mut rif = RipInterface::new(ifname).unwrap();
            let _ = rif.enable_rip(RipVersion::RIPv2);
            let _ = rif.enable_rip(RipVersion::RIPng);
            rif.set_auth_pw(Some("foo_bar_baz"));

            {
                rip.lock().unwrap().add_interface(rif.clone());
            }

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

            rif.send(&RipPacket::new(
                RipCommand::Request,
                RipVersion::RIPv2,
                rte4_list.clone(),
            ));
            rif.send(&RipPacket::new(
                RipCommand::Response,
                RipVersion::RIPv2,
                rte4_list.clone(),
            ));

            rif.send(&RipPacket::new(
                RipCommand::Request,
                RipVersion::RIPng,
                rte6_list.clone(),
            ));
            rif.send(&RipPacket::new(
                RipCommand::Response,
                RipVersion::RIPng,
                rte6_list.clone(),
            ));

            let rte4_withdraw = vec![RouteTableEntry::Ipv4Prefix(Rte4Prefix {
                afi: RipV2AddressFamily::Inet,
                tag: 150_u16,
                addr: Ipv4Addr::from_str("30.0.0.0").unwrap(),
                mask: Ipv4Addr::from_str("255.0.0.0").unwrap().to_bits(),
                nh: Ipv4Addr::from_str("192.168.0.55").unwrap(),
                metric: u32::from(RipPacket::INFINITY_METRIC),
            })];
            rif.send(&RipPacket::new(
                RipCommand::Response,
                RipVersion::RIPv2,
                rte4_withdraw.clone(),
            ));
        }
        "listener" => std::thread::scope(|s| {
            let mut rip = Rip::new();

            let mut rif = RipInterface::new(ifname).unwrap();
            let _ = rif.enable_rip(RipVersion::RIPv2);
            let _ = rif.enable_rip(RipVersion::RIPng);
            rif.set_auth_pw(Some("foo_bar_baz"));
            rip.add_interface(rif.clone());

            let ripv2_sock = rif.socket(RipVersion::RIPv2).unwrap();
            let ripng_sock = rif.socket(RipVersion::RIPng).unwrap();

            let rip = Arc::new(Mutex::new(rip));
            let ripv2 = rip.clone();
            let ripng = rip.clone();

            s.spawn(move || {
                rip_listen(&RipVersion::RIPv2, &ripv2_sock, ripv2);
            });

            s.spawn(move || {
                rip_listen(&RipVersion::RIPng, &ripng_sock, ripng);
            });

            loop {
                println!("[MAIN THREAD]: {:#?}\n", rip.lock().unwrap().db4());
                println!("[MAIN THREAD]: {:#?}\n", rip.lock().unwrap().db6());
                let _ = sleep(Duration::from_secs(10));
            }
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
