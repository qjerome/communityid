#![deny(unused_imports)]

//! This crate provides a practical implementation of the Community ID 
//! standard (https://github.com/corelight/community-id-spec) for network
//! flow hashing.
//! 
//! # Features
//! 
//! * `serde`: when enabled implements `serde::Serialize` and `serde::Deserialize` traits
//! 
//! # Example
//! 
//! ```
//! use communityid::{Protocol, Flow};
//! use std::net::Ipv4Addr;
//! 
//! let f = Flow::new(Protocol::UDP, Ipv4Addr::new(192,168,1,42).into(), 4242, Ipv4Addr::new(8,8,8,8).into(), 53);
//! let f2 = Flow::new(Protocol::UDP,  Ipv4Addr::new(8,8,8,8).into(), 53, Ipv4Addr::new(192,168,1,42).into(), 4242);
//! 
//! // community-id can be base64 encoded
//! assert_eq!(f.community_id_v1(0).base64(), "1:vTdrngJjlP5eZ9mw9JtnKyn99KM=");
//! 
//! // community-id can be hex encoded
//! assert_eq!(f2.community_id_v1(0).hexdigest(), "1:bd376b9e026394fe5e67d9b0f49b672b29fdf4a3");
//! 
//! // we can test equality between two community-ids
//! assert_eq!(f.community_id_v1(0), f2.community_id_v1(0));
//! ``` 

use std::net::IpAddr;

use base64::prelude::*;
use sha1::{Digest, Sha1};

#[cfg(feature = "serde")]
use serde::{
    de::{Deserialize, Deserializer, Visitor},
    ser::{Serialize, Serializer},
};

#[inline(always)]
fn serialize_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    }
}

#[repr(u16)]
enum IcmpType {
    EchoReply = 0,
    Echo = 8,
    RtrAdvert = 9,
    RtrSolicit = 10,
    Tstamp = 13,
    TstampReply = 14,
    Info = 15,
    InfoReply = 16,
    Mask = 17,
    MaskReply = 18,
}

fn icmp4_port_equivalent(p1: u16, p2: u16) -> (u16, u16, bool) {
    match p1 {
        t if t == IcmpType::Echo as u16 => (t, IcmpType::EchoReply as u16, false),
        t if t == IcmpType::EchoReply as u16 => (t, IcmpType::Echo as u16, false),
        t if t == IcmpType::Tstamp as u16 => (t, IcmpType::TstampReply as u16, false),
        t if t == IcmpType::TstampReply as u16 => (t, IcmpType::Tstamp as u16, false),
        t if t == IcmpType::Info as u16 => (t, IcmpType::InfoReply as u16, false),
        t if t == IcmpType::InfoReply as u16 => (t, IcmpType::Info as u16, false),
        t if t == IcmpType::RtrSolicit as u16 => (t, IcmpType::RtrAdvert as u16, false),
        t if t == IcmpType::RtrAdvert as u16 => (t, IcmpType::RtrSolicit as u16, false),
        t if t == IcmpType::Mask as u16 => (t, IcmpType::MaskReply as u16, false),
        t if t == IcmpType::MaskReply as u16 => (t, IcmpType::Mask as u16, false),
        _ => (p1, p2, true),
    }
}

#[repr(u16)]
enum Icmp6Type {
    EchoRequest = 128,
    EchoReply = 129,
    MldListenerQuery = 130,
    MldListenerReport = 131,
    NdRouterSolicit = 133,
    NdRouterAdvert = 134,
    NdNeighborSolicit = 135,
    NdNeighborAdvert = 136,
    WruRequest = 139,
    WruReply = 140,
    HaadRequest = 144,
    HaadReply = 145,
}

fn icmp6_port_equivalent(p1: u16, p2: u16) -> (u16, u16, bool) {
    match p1 {
        t if t == Icmp6Type::EchoRequest as u16 => (t, Icmp6Type::EchoReply as u16, false),
        t if t == Icmp6Type::EchoReply as u16 => (t, Icmp6Type::EchoRequest as u16, false),
        t if t == Icmp6Type::MldListenerQuery as u16 => {
            (t, Icmp6Type::MldListenerReport as u16, false)
        }
        t if t == Icmp6Type::MldListenerReport as u16 => {
            (t, Icmp6Type::MldListenerQuery as u16, false)
        }
        t if t == Icmp6Type::NdRouterSolicit as u16 => (t, Icmp6Type::NdRouterAdvert as u16, false),
        t if t == Icmp6Type::NdRouterAdvert as u16 => (t, Icmp6Type::NdRouterSolicit as u16, false),
        t if t == Icmp6Type::NdNeighborSolicit as u16 => {
            (t, Icmp6Type::NdNeighborAdvert as u16, false)
        }
        t if t == Icmp6Type::NdNeighborAdvert as u16 => {
            (t, Icmp6Type::NdNeighborSolicit as u16, false)
        }
        t if t == Icmp6Type::WruRequest as u16 => (t, Icmp6Type::WruReply as u16, false),
        t if t == Icmp6Type::WruReply as u16 => (t, Icmp6Type::WruRequest as u16, false),
        t if t == Icmp6Type::HaadRequest as u16 => (t, Icmp6Type::HaadReply as u16, false),
        t if t == Icmp6Type::HaadReply as u16 => (t, Icmp6Type::HaadRequest as u16, false),
        _ => (p1, p2, true),
    }
}

/// Enumeration holding the supported protocols by the community-id standard
#[derive(Debug, Clone, Copy, Hash)]
#[repr(u8)]
pub enum Protocol {
    ICMP = 1,
    TCP = 6,
    UDP = 17,
    ICMP6 = 58,
    SCTP = 132,
}

impl Protocol {
    /// Converts a protocol into a [Flow]
    /// 
    /// Example
    /// 
    /// ```
    /// use communityid::{Protocol};
    /// use std::net::Ipv4Addr;
    /// 
    /// let f = Protocol::UDP.into_flow(Ipv4Addr::new(192,168,1,42).into(), 4242, Ipv4Addr::new(8,8,8,8).into(), 53);
    /// 
    /// assert_eq!(f.community_id_v1(0).base64(), "1:vTdrngJjlP5eZ9mw9JtnKyn99KM=");
    /// ```
    #[inline]
    pub fn into_flow(self, src_ip: IpAddr, src_port: u16, dst_ip: IpAddr, dst_port:u16) -> Flow{
        Flow::new(self, src_ip, src_port, dst_ip, dst_port)
    }
}


/// Enumeration representing a community-id
#[derive(Hash, PartialEq)]
pub enum CommunityId {
    V1([u8; 20]),
}

#[cfg(feature = "serde")]
impl Serialize for CommunityId{
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer {
        serializer.serialize_str(&self.base64())
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for CommunityId {
    fn deserialize<D>(deserializer: D) -> Result<CommunityId, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct CommunityIdVisitor;

        impl<'de> Visitor<'de> for CommunityIdVisitor {
            type Value = CommunityId;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("expecting a community-id base64 encoded")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let (version, encoded) =  v.split_once(':').ok_or(E::custom("wrong community id format"))?;

                match version {
                    "1" => {
                        let v = BASE64_STANDARD.decode(encoded).map_err(E::custom)?;
                        let mut data = [0u8;20];
                        if data.len() != v.len() {
                            return Err(E::custom("data must be 20 bytes long"));
                        }
                        data.copy_from_slice(&v);
                        Ok(CommunityId::V1(data))
                    }
                    _=> Err(E::custom(format!("unknown community-id version: {}", version)))
                }
            }
        }

        deserializer.deserialize_string(CommunityIdVisitor)
    }
}

impl std::fmt::Debug for CommunityId{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.hexdigest())
    }
}

impl CommunityId {
    /// Encodes the current community-id in its base64 representation
    #[inline(always)]
    pub fn base64(&self) -> String {
        match self {
            Self::V1(data) => format!("1:{}", BASE64_STANDARD.encode(data)),
        }
    }

    /// Encodes the current community-id in its hexadecimal digest representation
    /// 
    /// Example
    /// 
    /// ```
    /// use communityid::{Protocol, Flow};
    /// use std::net::Ipv4Addr;
    /// 
    /// let f = Flow::new(Protocol::UDP, Ipv4Addr::new(192,168,1,42).into(), 4242, Ipv4Addr::new(8,8,8,8).into(), 53);
    /// 
    /// assert_eq!(f.community_id_v1(0).hexdigest(), "1:bd376b9e026394fe5e67d9b0f49b672b29fdf4a3");
    /// ```
    #[inline(always)]
    pub fn hexdigest(&self) -> String {
        match self {
            Self::V1(data) => 
        format!("1:{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", data[0],data[1],data[2],data[3],data[4],data[5],data[6],data[7],data[8],data[9],data[10],data[11],data[12],data[13],data[14],data[15],data[16],data[17],data[18],data[19])
        }
    }
}

/// Structure representing a network flow
#[derive(Debug, Clone, Copy, Hash)]
pub struct Flow {
    proto: Protocol,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    one_way: bool,
}

impl Flow {
    /// Creates a new flow from parameters
    #[inline]
    pub fn new(
        proto: Protocol,
        src_ip: IpAddr,
        src_port: u16,
        dst_ip: IpAddr,
        dst_port: u16,
    ) -> Self {
        let (src_port, dst_port, one_way) = match proto {
            Protocol::ICMP => icmp4_port_equivalent(src_port, dst_port),
            Protocol::ICMP6 => icmp6_port_equivalent(src_port, dst_port),
            _ => (src_port, dst_port, false),
        };

        Self {
            proto,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            one_way,
        }
    }

    #[inline(always)]
    fn order(&self) -> (IpAddr, u16, IpAddr, u16) {
        if self.one_way {
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        } else if (self.src_ip, self.src_port) > (self.dst_ip, self.dst_port) {
            (self.dst_ip, self.dst_port, self.src_ip, self.src_port)
        } else {
            (self.src_ip, self.src_port, self.dst_ip, self.dst_port)
        }
    }

    /// Computes the [CommunityId] corresponding to that Flow
    #[inline]
    pub fn community_id_v1(&self, seed: u16) -> CommunityId {
        // swap addresses and ports if necessary to ensure consistency.
        let (src_ip, src_port, dst_ip, dst_port) = self.order();

        let mut hasher = Sha1::new();

        // seed
        hasher.update(seed.to_be_bytes());
        // src ip
        hasher.update(serialize_ip(src_ip));
        // dest ip
        hasher.update(serialize_ip(dst_ip));
        // protocol
        hasher.update([self.proto as u8]);
        // padding
        hasher.update([0]);
        // src port be
        hasher.update(src_port.to_be_bytes());
        // dst port be
        hasher.update(dst_port.to_be_bytes());

        CommunityId::V1(hasher.finalize().into())
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    macro_rules! flow {
        ($proto:expr, $src_ip:literal, $src_port:literal, $dst_ip:literal, $dst_port:literal) => {
            Flow::new(
                $proto,
                IpAddr::from_str($src_ip).unwrap(),
                $src_port,
                IpAddr::from_str($dst_ip).unwrap(),
                $dst_port,
            )
        };
    }

    #[test]
    fn tcp_reorder() {
        let f = flow!(Protocol::TCP, "192.168.1.42", 42, "192.168.1.42", 41);

        assert_eq!(
            "1:eRcf7I/xocOxnYo5pbJBV5NhVm0=",
            f.community_id_v1(0).base64()
        );

        let f = flow!(Protocol::TCP, "192.168.1.42", 41, "192.168.1.42", 42);
        assert_eq!(
            "1:eRcf7I/xocOxnYo5pbJBV5NhVm0=",
            f.community_id_v1(0).base64()
        );
    }

    #[test]
    fn tcp_test() {
        let f = Flow::new(
            Protocol::TCP,
            IpAddr::from_str("192.168.1.10").unwrap(),
            12345,
            IpAddr::from_str("192.168.1.20").unwrap(),
            80,
        );

        assert_eq!(
            "1:To62PWNVuiriSZDHqB4YZp+VAYM=",
            f.community_id_v1(0).base64()
        );

        assert_eq!(
            "1:4e8eb63d6355ba2ae24990c7a81e18669f950183",
            f.community_id_v1(0).hexdigest()
        );
    }

    #[test]
    fn test_icmp() {
        assert_eq!(
            "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=",
            flow!(Protocol::ICMP, "192.168.0.89", 8, "192.168.0.1", 0)
                .community_id_v1(0)
                .base64()
        );

        assert_eq!(
            "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=",
            flow!(Protocol::ICMP, "192.168.0.1", 0, "192.168.0.89", 8)
                .community_id_v1(0)
                .base64()
        );

        assert_eq!(
            "1:3o2RFccXzUgjl7zDpqmY7yJi8rI=",
            flow!(Protocol::ICMP, "192.168.0.89", 20, "192.168.0.1", 0)
                .community_id_v1(0)
                .base64()
        );

        assert_eq!(
            "1:tz/fHIDUHs19NkixVVoOZywde+I=",
            flow!(Protocol::ICMP, "192.168.0.89", 20, "192.168.0.1", 1)
                .community_id_v1(0)
                .base64()
        );

        assert_eq!(
            "1:X0snYXpgwiv9TZtqg64sgzUn6Dk=",
            flow!(Protocol::ICMP, "192.168.0.1", 0, "192.168.0.89", 20)
                .community_id_v1(0)
                .base64()
        );
    }

    #[test]
    fn test_icmp6() {
        assert_eq!(
            "1:dGHyGvjMfljg6Bppwm3bg0LO8TY=",
            flow!(
                Protocol::ICMP6,
                "fe80::200:86ff:fe05:80da",
                135,
                "fe80::260:97ff:fe07:69ea",
                0
            )
            .community_id_v1(0)
            .base64()
        );

        assert_eq!(
            "1:dGHyGvjMfljg6Bppwm3bg0LO8TY=",
            flow!(
                Protocol::ICMP6,
                "fe80::260:97ff:fe07:69ea",
                136,
                "fe80::200:86ff:fe05:80da",
                0
            )
            .community_id_v1(0)
            .base64()
        );

        assert_eq!(
            "1:NdobDX8PQNJbAyfkWxhtL2Pqp5w=",
            flow!(
                Protocol::ICMP6,
                "3ffe:507:0:1:260:97ff:fe07:69ea",
                3,
                "3ffe:507:0:1:200:86ff:fe05:80da",
                0
            )
            .community_id_v1(0)
            .base64()
        );

        assert_eq!(
            "1:/OGBt9BN1ofenrmSPWYicpij2Vc=",
            flow!(
                Protocol::ICMP6,
                "3ffe:507:0:1:200:86ff:fe05:80da",
                3,
                "3ffe:507:0:1:260:97ff:fe07:69ea",
                0
            )
            .community_id_v1(0)
            .base64()
        );
    }

    #[test]
    fn test_serde(){
        let f = flow!(Protocol::TCP, "192.168.1.42", 41, "192.168.1.42", 42);

        assert_eq!(
            r#""1:eRcf7I/xocOxnYo5pbJBV5NhVm0=""#,
            serde_json::to_string(&f.community_id_v1(0)).unwrap()
        );

        assert_eq!(
            f.community_id_v1(0),
            serde_json::from_str(r#""1:eRcf7I/xocOxnYo5pbJBV5NhVm0=""#).unwrap()
        );
    }
}
