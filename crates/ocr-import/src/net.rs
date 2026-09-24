//! Just enough link/network/transport parsing to reach a UDP payload.
//!
//! GSMTAP rides on UDP, and a pcap file usually stores that UDP datagram wrapped
//! in a full link-layer frame. This module peels the common wrappings down to the
//! UDP payload and reports the ports, so the importer can pick out datagrams on the
//! GSMTAP port. It is intentionally small: it recognises the link types that carry
//! IPv4 in the captures this project targets, and returns [`None`] (a skip, not an
//! error) for anything it doesn't handle. Every read is bounds-checked.
//!
//! Recognised link-layer types (DLT / LINKTYPE_*):
//! - `1`   Ethernet (with one optional 802.1Q VLAN tag)
//! - `12`  raw IP, and `101` "raw" (both bare IPv4/IPv6)
//! - `228` IPv4, `229` IPv6
//! - `113` Linux "cooked" capture v1 (SLL)
//!
//! Only IPv4 + UDP is followed to a payload; IPv6, non-UDP, and fragmented IPv4 are
//! skipped (returned as [`None`]). Extending this is one match arm — see the crate
//! docs "adding a format".

/// LINKTYPE_ETHERNET.
pub const LINKTYPE_ETHERNET: u32 = 1;
/// LINKTYPE_RAW (bare IP), and the older DLT_RAW value some tools write.
pub const LINKTYPE_RAW: u32 = 101;
pub const LINKTYPE_RAW_ALT: u32 = 12;
/// LINKTYPE_IPV4 / LINKTYPE_IPV6 (bare IP of a known family).
pub const LINKTYPE_IPV4: u32 = 228;
pub const LINKTYPE_IPV6: u32 = 229;
/// LINKTYPE_LINUX_SLL (Linux "cooked" capture, v1).
pub const LINKTYPE_LINUX_SLL: u32 = 113;

const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_VLAN: u16 = 0x8100;
const IP_PROTO_UDP: u8 = 17;

/// A UDP datagram extracted from a captured frame.
#[derive(Debug, Clone, Copy)]
pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub payload: &'a [u8],
}

/// Peel a captured link-layer frame down to its UDP payload, if it is IPv4 + UDP.
///
/// Returns [`None`] for anything not carrying an IPv4/UDP datagram (a different
/// link type, IPv6, a non-UDP protocol, a fragmented datagram, or a frame too
/// short to hold the headers). This is a "skip", not a hard error: a capture can
/// legitimately mix GSMTAP with other traffic.
pub fn udp_payload(linktype: u32, frame: &[u8]) -> Option<Udp<'_>> {
    let ip = match linktype {
        LINKTYPE_ETHERNET => ethernet_ipv4(frame)?,
        LINKTYPE_RAW | LINKTYPE_RAW_ALT | LINKTYPE_IPV4 => frame,
        LINKTYPE_LINUX_SLL => linux_sll_ipv4(frame)?,
        // IPv6-only or unknown link types: nothing to follow here.
        _ => return None,
    };
    ipv4_udp(ip)
}

/// From an Ethernet frame, return the IPv4 packet slice (skipping one VLAN tag).
fn ethernet_ipv4(frame: &[u8]) -> Option<&[u8]> {
    // dst(6) + src(6) + ethertype(2) = 14.
    let ethertype = u16::from_be_bytes([*frame.get(12)?, *frame.get(13)?]);
    if ethertype == ETHERTYPE_IPV4 {
        return frame.get(14..);
    }
    if ethertype == ETHERTYPE_VLAN {
        // 802.1Q: 2 bytes TCI then the real ethertype, IP follows at 18.
        let inner = u16::from_be_bytes([*frame.get(16)?, *frame.get(17)?]);
        if inner == ETHERTYPE_IPV4 {
            return frame.get(18..);
        }
    }
    None
}

/// From a Linux SLL v1 frame (16-byte header), return the IPv4 packet slice.
fn linux_sll_ipv4(frame: &[u8]) -> Option<&[u8]> {
    // SLL header: packet_type(2) arphrd(2) addr_len(2) addr(8) protocol(2) = 16.
    let protocol = u16::from_be_bytes([*frame.get(14)?, *frame.get(15)?]);
    if protocol == ETHERTYPE_IPV4 {
        return frame.get(16..);
    }
    None
}

/// From an IPv4 packet, return its UDP datagram (ports + payload), or [`None`].
fn ipv4_udp(ip: &[u8]) -> Option<Udp<'_>> {
    let ver_ihl = *ip.first()?;
    // High nibble = version (must be 4); low nibble = header length in 32-bit words.
    if ver_ihl >> 4 != 4 {
        return None;
    }
    let ihl = (ver_ihl & 0x0f) as usize * 4;
    if ihl < 20 {
        return None;
    }
    if *ip.get(9)? != IP_PROTO_UDP {
        return None;
    }
    // Flags/fragment-offset: skip any fragment that is not the whole datagram.
    let frag = u16::from_be_bytes([*ip.get(6)?, *ip.get(7)?]);
    let more_fragments = frag & 0x2000 != 0;
    let frag_offset = frag & 0x1fff;
    if more_fragments || frag_offset != 0 {
        return None;
    }
    let udp = ip.get(ihl..)?;
    udp_datagram(udp)
}

/// Parse a UDP datagram: ports, then the payload after the 8-byte header.
fn udp_datagram(udp: &[u8]) -> Option<Udp<'_>> {
    let src_port = u16::from_be_bytes([*udp.first()?, *udp.get(1)?]);
    let dst_port = u16::from_be_bytes([*udp.get(2)?, *udp.get(3)?]);
    // The length field is advisory here; we trust the bytes actually captured.
    let payload = udp.get(8..)?;
    Some(Udp {
        src_port,
        dst_port,
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ipv4_udp(src: u16, dst: u16, body: &[u8]) -> Vec<u8> {
        let mut udp = Vec::new();
        udp.extend_from_slice(&src.to_be_bytes());
        udp.extend_from_slice(&dst.to_be_bytes());
        udp.extend_from_slice(&((8 + body.len()) as u16).to_be_bytes());
        udp.extend_from_slice(&0u16.to_be_bytes());
        udp.extend_from_slice(body);
        let mut ip = vec![0x45, 0x00];
        ip.extend_from_slice(&((20 + udp.len()) as u16).to_be_bytes());
        ip.extend_from_slice(&[0, 0, 0, 0, 64, 17, 0, 0]); // id, frag, ttl, proto, csum
        ip.extend_from_slice(&[10, 0, 0, 1, 10, 0, 0, 2]);
        ip.extend_from_slice(&udp);
        ip
    }

    #[test]
    fn raw_ipv4_udp_payload() {
        let ip = ipv4_udp(1000, 4729, b"gtap");
        let u = udp_payload(LINKTYPE_RAW, &ip).expect("udp");
        assert_eq!(u.dst_port, 4729);
        assert_eq!(u.payload, b"gtap");
    }

    #[test]
    fn ethernet_wraps_ipv4() {
        let ip = ipv4_udp(1, 4729, b"z");
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x0800u16.to_be_bytes());
        eth.extend_from_slice(&ip);
        let u = udp_payload(LINKTYPE_ETHERNET, &eth).expect("udp");
        assert_eq!(u.payload, b"z");
    }

    #[test]
    fn vlan_tag_is_skipped() {
        let ip = ipv4_udp(1, 4729, b"v");
        let mut eth = vec![0u8; 12];
        eth.extend_from_slice(&0x8100u16.to_be_bytes()); // VLAN
        eth.extend_from_slice(&0x0000u16.to_be_bytes()); // TCI
        eth.extend_from_slice(&0x0800u16.to_be_bytes()); // inner ethertype
        eth.extend_from_slice(&ip);
        assert!(udp_payload(LINKTYPE_ETHERNET, &eth).is_some());
    }

    #[test]
    fn non_udp_protocol_is_none() {
        let mut ip = ipv4_udp(1, 4729, b"x");
        ip[9] = 6; // TCP
        assert!(udp_payload(LINKTYPE_RAW, &ip).is_none());
    }

    #[test]
    fn fragmented_ipv4_is_none() {
        let mut ip = ipv4_udp(1, 4729, b"x");
        ip[6] = 0x20; // more-fragments flag
        assert!(udp_payload(LINKTYPE_RAW, &ip).is_none());
    }

    #[test]
    fn unknown_linktype_is_none() {
        let ip = ipv4_udp(1, 4729, b"x");
        assert!(udp_payload(9999, &ip).is_none());
    }

    #[test]
    fn short_frames_never_panic() {
        let ip = ipv4_udp(1, 4729, b"payload");
        for lt in [LINKTYPE_ETHERNET, LINKTYPE_RAW, LINKTYPE_LINUX_SLL] {
            for n in 0..=ip.len() {
                let _ = udp_payload(lt, &ip[..n]);
            }
        }
    }
}
