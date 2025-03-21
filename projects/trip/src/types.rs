use crate::helpers::*;
use crate::packet::*;
use ipnet::{Ipv4Net, Ipv6Net};
use socket2::{self, Domain, InterfaceIndexOrAddress, SockAddr, Socket, Type};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, UdpSocket},
    sync::{Arc, Mutex},
};

pub type RipV2Db = BTreeMap<Ipv4Net, BTreeSet<RipPathInfo>>;
pub type RipNgDb = BTreeMap<Ipv6Net, BTreeSet<RipPathInfo>>;

#[derive(Clone, Debug)]
pub struct RipDb {
    ipv4: Arc<Mutex<RipV2Db>>,
    ipv6: Arc<Mutex<RipNgDb>>,
}

impl RipDb {
    pub fn new() -> Self {
        Self {
            ipv4: Arc::new(Mutex::new(BTreeMap::new())),
            ipv6: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub fn ripv2(&self) -> RipV2Db {
        self.ipv4.lock().unwrap().clone()
    }

    pub fn ripng(&self) -> RipNgDb {
        self.ipv6.lock().unwrap().clone()
    }
}

pub struct RipInterface {
    // XXX: Convert to &str and learn lifetimes?
    ifname: String,
    ifindex: u32,
    #[allow(dead_code)]
    mtu: usize,
    ripv2_sock: Option<Arc<UdpSocket>>,
    ripng_sock: Option<Arc<UdpSocket>>,
    auth: Option<(RipV2AuthType, u128)>,
}

impl RipInterface {
    pub fn new(ifname: String) -> Option<Self> {
        let ifindex = ifname_to_ifindex(&ifname).ok()?;
        Some(Self {
            ifname,
            ifindex,
            mtu: ASSUMED_MTU,
            ripv2_sock: None,
            ripng_sock: None,
            auth: None,
        })
    }

    pub fn ripv2_socket(&self) -> Option<Arc<UdpSocket>> {
        match &self.ripv2_sock {
            None => None,
            Some(s) => Some(s.clone()),
        }
    }

    pub fn ripng_socket(&self) -> Option<Arc<UdpSocket>> {
        match &self.ripng_sock {
            None => None,
            Some(s) => Some(s.clone()),
        }
    }

    pub fn enable_ripv2(&mut self) -> std::io::Result<()> {
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
        self.ripv2_sock = Some(Arc::new(ripv2_sock.into()));
        Ok(())
    }

    pub fn enable_ripng(&mut self) -> std::io::Result<()> {
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
        self.ripng_sock = Some(Arc::new(ripng_sock.into()));
        Ok(())
    }

    pub fn set_auth_pw(&mut self, pw: Option<&str>) {
        self.auth = match pw {
            Some(p) => {
                let mut pw_buf = [0u8; 16];
                pw_buf[..p.len()].copy_from_slice(p.as_bytes());
                let pw_bytes = u128::from_ne_bytes(pw_buf);
                Some((RipV2AuthType::Password, pw_bytes))
            }
            None => None,
        };
    }

    pub fn send_ripv2(&self, rp: &RipPacket) {
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

    pub fn send_ripng(&self, rp: &RipPacket) {
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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RipPathInfo {
    nh: IpAddr,
    ifindex: u32,
    metric: u8,
    tag: u16,
}

impl RipPathInfo {
    pub fn new(nh: IpAddr, ifindex: u32, metric: u8, tag: u16) -> Self {
        Self {
            nh,
            ifindex,
            metric,
            tag,
        }
    }
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
