use crate::helpers::{ifname_to_ifindex, init_logger};
use crate::packet::{
    RipPacket, RipV2AuthType, RipVersion, ASSUMED_MTU, RIPNG_BIND, RIPNG_DEST, RIPNG_GROUP,
    RIPV2_BIND, RIPV2_DEST, RIPV2_GROUP,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use slog::Logger;
use socket2::{self, Domain, InterfaceIndexOrAddress, SockAddr, Socket, Type};
use std::{
    cmp::{Ord, Ordering},
    collections::{BTreeMap, BTreeSet},
    fmt::Debug,
    net::{IpAddr, UdpSocket},
    sync::{Arc, Mutex},
};

#[derive(Debug)]
pub struct RipRouter {
    pub db4: Arc<Mutex<RipDb<Ipv4Net>>>,
    pub db6: Arc<Mutex<RipDb<Ipv6Net>>>,
    pub interfaces: BTreeMap<String, RipInterface>,
    pub log: Logger,
}

impl RipRouter {
    pub fn new() -> Self {
        Self {
            db4: Arc::new(Mutex::new(RipDb::new())),
            db6: Arc::new(Mutex::new(RipDb::new())),
            interfaces: BTreeMap::new(),
            log: init_logger(),
        }
    }

    pub fn db4(&self) -> RipDb<Ipv4Net> {
        self.db4.lock().unwrap().clone()
    }

    pub fn db6(&self) -> RipDb<Ipv6Net> {
        self.db6.lock().unwrap().clone()
    }

    pub fn insert_prefix_path(&mut self, pfx: IpNet, path: &RipPathInfo) {
        match pfx {
            IpNet::V4(p4) => self.db4.lock().unwrap().insert(p4, path),
            IpNet::V6(p6) => self.db6.lock().unwrap().insert(p6, path),
        }
    }

    pub fn remove_prefix_path(&mut self, pfx: IpNet, path: &RipPathInfo) {
        match pfx {
            IpNet::V4(p4) => self.db4.lock().unwrap().remove(&p4, path),
            IpNet::V6(p6) => self.db6.lock().unwrap().remove(&p6, path),
        }
    }

    pub fn add_interface(&mut self, rif: RipInterface) {
        self.interfaces.insert(rif.ifname.clone(), rif);
    }
}

#[derive(Clone, Debug)]
pub struct RipDb<P>(BTreeMap<P, BTreeSet<RipPathInfo>>);

impl<P> RipDb<P>
where
    P: Clone + Ord + Debug,
{
    pub fn new() -> Self {
        Self(BTreeMap::new())
    }

    pub fn insert(&mut self, pfx: P, path: &RipPathInfo) {
        let nh_set = self.0.entry(pfx).or_default();
        nh_set.insert(path.clone());
    }

    pub fn remove(&mut self, pfx: &P, path: &RipPathInfo) {
        match self.0.get_mut(pfx) {
            // no paths: remove the key
            None => {
                self.0.remove(pfx);
            }
            // some paths: remove this path
            Some(nh_set) => {
                let _ = nh_set.remove(path);
                // we just removed the last path: remove the key
                if nh_set.is_empty() {
                    self.0.remove(pfx);
                }
            }
        };
    }
}

#[derive(Clone, Debug)]
pub struct RipInterface {
    // XXX: Convert to &str and learn lifetimes?
    ifname: String,
    ifindex: u32,
    #[allow(dead_code)]
    mtu: usize,
    sock4: Option<Arc<UdpSocket>>,
    sock6: Option<Arc<UdpSocket>>,
    auth: Option<(RipV2AuthType, u128)>,
}

impl RipInterface {
    pub fn new(ifname: String) -> Option<Self> {
        let ifindex = ifname_to_ifindex(&ifname).ok()?;
        Some(Self {
            ifname,
            ifindex,
            mtu: ASSUMED_MTU,
            sock4: None,
            sock6: None,
            auth: None,
        })
    }

    pub fn socket(&self, ver: RipVersion) -> Option<Arc<UdpSocket>> {
        let sock = match ver {
            RipVersion::RIPv2 => &self.sock4,
            RipVersion::RIPng => &self.sock6,
        };
        sock.as_ref().map(std::clone::Clone::clone)
    }

    pub fn enable_rip(&mut self, ver: RipVersion) -> std::io::Result<()> {
        // early return if already enabled
        match ver {
            RipVersion::RIPv2 => {
                if self.sock4.is_some() {
                    return Ok(());
                }
            }
            RipVersion::RIPng => {
                if self.sock6.is_some() {
                    return Ok(());
                }
            }
        };

        let sock = match ver {
            RipVersion::RIPv2 => Socket::new(Domain::IPV4, Type::DGRAM, None)?,
            RipVersion::RIPng => Socket::new(Domain::IPV6, Type::DGRAM, None)?,
        };
        sock.set_reuse_address(true)?;
        sock.bind_device(Some(self.ifname.as_bytes()))?;
        match ver {
            RipVersion::RIPv2 => {
                sock.bind(&SockAddr::from(RIPV2_BIND))?;
                sock.set_multicast_all_v4(true)?;
                // ripv2_sock.set_multicast_if_v4(&V4_IFADDR)?;
                // XXX: we may want to disable this at some point
                sock.set_multicast_loop_v4(true)?;
                sock.join_multicast_v4_n(
                    &RIPV2_GROUP,
                    &InterfaceIndexOrAddress::Index(self.ifindex),
                )?;
                // for whatever reason, the socket doesn't rx packets sent to 224.0.0.9
                // if we call connect() against 224.0.0.9... so leave this unconnected for now?
                // ripv2_sock.connect(&SockAddr::from(RIPV2_DEST))?;
                self.sock4 = Some(Arc::new(sock.into()));
            }
            RipVersion::RIPng => {
                // set_only_v6() fails with EINVAL if called after bind(), so call it here
                sock.set_only_v6(true)?;
                sock.bind(&SockAddr::from(RIPNG_BIND))?;
                sock.set_multicast_all_v6(true)?;
                // sock.set_multicast_if_v6(ifindex)?;
                // XXX: we may want to disable this at some point
                sock.set_multicast_loop_v6(true)?;
                sock.join_multicast_v6(&RIPNG_GROUP, self.ifindex)?;
                self.sock6 = Some(Arc::new(sock.into()));
            }
        }
        Ok(())
    }

    // XXX: pub fn disable_rip(&mut self, ver: RipVersion)
    // figure out the "right" way to close a socket

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

    pub fn send(&self, rp: &RipPacket) {
        let (socket, dst) = match rp.version() {
            RipVersion::RIPv2 => (&self.sock4, &RIPV2_DEST),
            RipVersion::RIPng => (&self.sock6, &RIPNG_DEST),
        };
        match socket {
            None => (),
            Some(ref sock) => {
                // use send_to() instead of send() because the socket isn't connect()'d
                if let Ok(bytes_sent) = sock.send_to(&rp.to_byte_vec(), dst) {
                    println!(
                        "tx rip pkt ({bytes_sent} bytes) from {} to {dst}:\n{rp}\n",
                        sock.local_addr().unwrap()
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
