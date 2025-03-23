use crate::packet::*;
use crate::types::*;
use std::{
    ffi::CString,
    net::UdpSocket,
    sync::{Arc, Mutex},
};

pub fn ifname_to_ifindex(ifname: &str) -> Result<u32, std::ffi::NulError> {
    let ifindex = unsafe {
        let ifstr = CString::new(ifname)?.into_raw();
        let ifindex = libc::if_nametoindex(ifstr) as u32;
        drop(CString::from_raw(ifstr));
        ifindex
    };
    Ok(ifindex)
}

pub fn rip_listen(ver: &RipVersion, sock: &UdpSocket, rip: Arc<Mutex<Rip>>) {
    let mut buf = [0u8; 4096];
    println!(
        "listening for {} on {}",
        "RIPv2",
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
                    rip_pkt.process(rip.clone(), src_addr.ip());
                    match ver {
                        RipVersion::RIPv2 => {
                            println!("{ver} RIB: {:#?}\n", rip.lock().unwrap().db4())
                        }
                        RipVersion::RIPng => {
                            println!("{ver} RIB: {:#?}\n", rip.lock().unwrap().db6())
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
