use crate::helpers::*;
use crate::packet::*;
use crate::types::*;
use std::{
    env,
    net::{Ipv4Addr, Ipv6Addr},
    str::FromStr,
};

mod helpers;
mod packet;
mod types;

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
            rif.set_auth_pw(Some("foo_bar_baz"));

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

            rif.send_ripv2(&RipPacket::new(
                RipCommand::Request,
                &RipVersion::RIPv2,
                rte4_list.clone(),
            ));
            rif.send_ripv2(&RipPacket::new(
                RipCommand::Response,
                &RipVersion::RIPv2,
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
            rif.set_auth_pw(Some("foo_bar_baz"));

            let ripv2_sock = rif.ripv2_socket().unwrap();
            let ripng_sock = rif.ripng_socket().unwrap();

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
