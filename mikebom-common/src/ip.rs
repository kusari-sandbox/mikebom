/// no_std-compatible IP address wrapper.
///
/// Stores all addresses as 16-byte arrays. IPv4 addresses use the
/// IPv4-mapped IPv6 format (::ffff:x.x.x.x) so the kernel and
/// userspace share a single representation.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IpAddr {
    /// Raw address bytes. IPv4 uses bytes 12-15 with ::ffff prefix.
    pub octets: [u8; 16],
    /// 0 for IPv4, 1 for IPv6
    pub is_v6: u8,
    pub _padding: [u8; 3],
}

impl IpAddr {
    pub const fn new_v4(a: u8, b: u8, c: u8, d: u8) -> Self {
        let mut octets = [0u8; 16];
        // ::ffff:a.b.c.d
        octets[10] = 0xff;
        octets[11] = 0xff;
        octets[12] = a;
        octets[13] = b;
        octets[14] = c;
        octets[15] = d;
        Self {
            octets,
            is_v6: 0,
            _padding: [0; 3],
        }
    }

    pub const fn new_v6(octets: [u8; 16]) -> Self {
        Self {
            octets,
            is_v6: 1,
            _padding: [0; 3],
        }
    }

    pub const fn is_v4(&self) -> bool {
        self.is_v6 == 0
    }

    /// Extract the IPv4 octets (bytes 12-15) if this is a v4 address.
    pub const fn v4_octets(&self) -> [u8; 4] {
        [
            self.octets[12],
            self.octets[13],
            self.octets[14],
            self.octets[15],
        ]
    }
}

#[cfg(feature = "std")]
impl core::fmt::Display for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_v4() {
            let o = self.v4_octets();
            write!(f, "{}.{}.{}.{}", o[0], o[1], o[2], o[3])
        } else {
            // Simplified IPv6 display (no :: compression)
            for i in 0..8 {
                if i > 0 {
                    write!(f, ":")?;
                }
                let hi = self.octets[i * 2];
                let lo = self.octets[i * 2 + 1];
                write!(f, "{:x}{:02x}", hi, lo)?;
            }
            Ok(())
        }
    }
}

#[cfg(feature = "std")]
impl core::fmt::Debug for IpAddr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "IpAddr({})", self)
    }
}

#[cfg(feature = "std")]
impl From<std::net::IpAddr> for IpAddr {
    fn from(addr: std::net::IpAddr) -> Self {
        match addr {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                Self::new_v4(o[0], o[1], o[2], o[3])
            }
            std::net::IpAddr::V6(v6) => Self::new_v6(v6.octets()),
        }
    }
}

#[cfg(feature = "std")]
impl From<IpAddr> for std::net::IpAddr {
    fn from(addr: IpAddr) -> Self {
        if addr.is_v4() {
            let o = addr.v4_octets();
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(o[0], o[1], o[2], o[3]))
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::from(addr.octets))
        }
    }
}

#[cfg(feature = "std")]
impl serde::Serialize for IpAddr {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let std_addr: std::net::IpAddr = (*self).into();
        serializer.serialize_str(&std_addr.to_string())
    }
}

#[cfg(feature = "std")]
impl<'de> serde::Deserialize<'de> for IpAddr {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        let addr: std::net::IpAddr = s.parse().map_err(serde::de::Error::custom)?;
        Ok(addr.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_round_trip() {
        let addr = IpAddr::new_v4(192, 168, 1, 1);
        assert!(addr.is_v4());
        assert_eq!(addr.v4_octets(), [192, 168, 1, 1]);
        assert_eq!(addr.to_string(), "192.168.1.1");
    }

    #[test]
    fn v6_creation() {
        let octets = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let addr = IpAddr::new_v6(octets);
        assert!(!addr.is_v4());
    }

    #[test]
    fn std_conversion_v4() {
        let std_addr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        let our_addr: IpAddr = std_addr.into();
        let back: std::net::IpAddr = our_addr.into();
        assert_eq!(std_addr, back);
    }

    #[test]
    fn serde_round_trip() {
        let addr = IpAddr::new_v4(127, 0, 0, 1);
        let json = serde_json::to_string(&addr).unwrap();
        assert_eq!(json, "\"127.0.0.1\"");
        let back: IpAddr = serde_json::from_str(&json).unwrap();
        assert_eq!(addr, back);
    }
}
