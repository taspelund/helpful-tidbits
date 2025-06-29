use crate::helpers::{get_dummy_rte_lists, rip_listen};
use crate::packet::{
    RipCommand, RipPacket, RipV2AddressFamily, RipVersion, RouteTableEntry, Rte4Prefix,
};
use crate::types::{RipInterface, RipRouter};
use std::thread::sleep;
use std::time::Duration;
use std::{
    env,
    net::Ipv4Addr,
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
            let router = Arc::new(Mutex::new(RipRouter::new()));

            let mut rif = RipInterface::new(ifname).unwrap();
            let _ = rif.enable_rip(RipVersion::RIPv2);
            let _ = rif.enable_rip(RipVersion::RIPng);
            rif.set_auth_pw(Some("foo_bar_baz"));

            {
                router.lock().unwrap().add_interface(rif.clone());
            }

            let (rte4_list, rte6_list) = get_dummy_rte_lists();

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
            let mut router = RipRouter::new();

            let mut rif = RipInterface::new(ifname).unwrap();
            let _ = rif.enable_rip(RipVersion::RIPv2);
            let _ = rif.enable_rip(RipVersion::RIPng);
            rif.set_auth_pw(Some("foo_bar_baz"));
            router.add_interface(rif.clone());

            let ripv2_sock = rif.socket(RipVersion::RIPv2).unwrap();
            let ripng_sock = rif.socket(RipVersion::RIPng).unwrap();

            let router = Arc::new(Mutex::new(router));
            let ripv2 = router.clone();
            let ripng = router.clone();

            s.spawn(move || {
                rip_listen(RipVersion::RIPv2, &ripv2_sock, &ripv2);
            });

            s.spawn(move || {
                rip_listen(RipVersion::RIPng, &ripng_sock, &ripng);
            });

            loop {
                println!("[MAIN THREAD]: {:#?}\n", router.lock().unwrap().db4());
                println!("[MAIN THREAD]: {:#?}\n", router.lock().unwrap().db6());
                sleep(Duration::from_secs(10));
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
