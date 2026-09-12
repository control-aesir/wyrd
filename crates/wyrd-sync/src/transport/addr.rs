//! Canonical bytes for a snapshot announcement's `node_addr` route.
//!
//! The announcement carries the route as opaque counted bytes; both
//! sides of the interpretation (authoring a serving address, planning a
//! fetch) land here. The encoding is hand-rolled canonical in the
//! control-frame style rather than serde: route-update classification
//! compares candidate bytes against recorded ones, so two runs over the
//! same address must encode identically or a benign reannouncement
//! degrades into a spurious route update.
//!
//! Layout v0: `version (1) ‖ node id (32) ‖ u32 LE ip count ‖ per ip
//! `family (1: 0x04 IPv4, 0x06 IPv6) ‖ ip octets ‖ u16 LE port` ‖
//! u32 LE relay count ‖ per relay `u32 LE length ‖ utf8 url`'.
//! The address set is a `BTreeSet`, so the encoding order is stable by
//! construction; decode additionally rejects any byte string that does
//! not re-encode identically, so exactly one encoding names an address.

use std::str::FromStr;

use iroh::{EndpointAddr, PublicKey, RelayUrl};

/// Canonical encoding version. Bumping it is a new `node_addr` encoding;
/// older versions stay decodable while devices migrate.
pub(crate) const NODE_ADDR_VERSION: u8 = 0x01;

/// Route bytes that fail the codec's structural checks.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("node_addr route bytes are malformed")]
pub struct NodeAddrError;

/// Encode a serving address into the announcement's opaque route bytes.
pub fn encode_node_addr(address: &EndpointAddr) -> Vec<u8> {
    let mut out = Vec::with_capacity(64);
    out.push(NODE_ADDR_VERSION);
    out.extend_from_slice(address.id.as_bytes());
    let ips: Vec<_> = address
        .addrs
        .iter()
        .filter_map(|addr| match addr {
            iroh::TransportAddr::Ip(socket) => Some(*socket),
            _ => None,
        })
        .collect();
    out.extend_from_slice(&(ips.len() as u32).to_le_bytes());
    for ip in ips {
        match ip {
            std::net::SocketAddr::V4(v4) => {
                out.push(0x04);
                out.extend_from_slice(&v4.ip().octets());
            }
            std::net::SocketAddr::V6(v6) => {
                out.push(0x06);
                out.extend_from_slice(&v6.ip().octets());
            }
        }
        out.extend_from_slice(&ip.port().to_le_bytes());
    }
    let relays: Vec<_> = address
        .addrs
        .iter()
        .filter_map(|addr| match addr {
            iroh::TransportAddr::Relay(url) => Some(url.clone()),
            _ => None,
        })
        .collect();
    out.extend_from_slice(&(relays.len() as u32).to_le_bytes());
    for relay in relays {
        let url = relay.to_string();
        out.extend_from_slice(&(url.len() as u32).to_le_bytes());
        out.extend_from_slice(url.as_bytes());
    }
    out
}

/// Decode route bytes back to a connectable address. Trailing garbage,
/// version drift, truncated fields, and non-canonical spellings (a
/// different byte order, duplicate addresses, or alternate URL text)
/// all fail closed: exactly one encoding names an address, so
/// route-update classification compares bytes without ambiguity.
pub fn decode_node_addr(bytes: &[u8]) -> Result<EndpointAddr, NodeAddrError> {
    if bytes.len() < 37 || bytes[0] != NODE_ADDR_VERSION {
        return Err(NodeAddrError);
    }
    let id_bytes: [u8; 32] = bytes[1..33].try_into().map_err(|_| NodeAddrError)?;
    let id = PublicKey::from_bytes(&id_bytes).map_err(|_| NodeAddrError)?;
    let mut address = EndpointAddr::new(id);
    let mut cursor = 33;
    let read_u16 = |cursor: usize| -> Result<u16, NodeAddrError> {
        bytes
            .get(cursor..cursor + 2)
            .map(|slice| u16::from_le_bytes(slice.try_into().expect("u16 slice")))
            .ok_or(NodeAddrError)
    };
    let read_u32 = |cursor: usize| -> Result<u32, NodeAddrError> {
        bytes
            .get(cursor..cursor + 4)
            .map(|slice| u32::from_le_bytes(slice.try_into().expect("u32 slice")))
            .ok_or(NodeAddrError)
    };
    let ip_count = read_u32(cursor)? as usize;
    cursor += 4;
    for _ in 0..ip_count {
        let (family, size) = match bytes.get(cursor) {
            Some(0x04) => (4usize, 4usize),
            Some(0x06) => (6, 16),
            _ => return Err(NodeAddrError),
        };
        let octets = bytes
            .get(cursor + 1..cursor + 1 + size)
            .ok_or(NodeAddrError)?;
        let port = read_u16(cursor + 1 + size)?;
        cursor += 1 + size + 2;
        let mut padded = [0u8; 16];
        padded[..size].copy_from_slice(octets);
        let ip = match family {
            4 => std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                <[u8; 4]>::try_from(&padded[..4]).expect("ipv4 octets"),
            )),
            _ => std::net::IpAddr::V6(std::net::Ipv6Addr::from(padded)),
        };
        address = address.with_ip_addr(std::net::SocketAddr::new(ip, port));
    }
    let relay_count = read_u32(cursor)? as usize;
    cursor += 4;
    for _ in 0..relay_count {
        let len = read_u32(cursor)? as usize;
        cursor += 4;
        let url = std::str::from_utf8(bytes.get(cursor..cursor + len).ok_or(NodeAddrError)?)
            .ok()
            .and_then(|s| RelayUrl::from_str(s).ok())
            .ok_or(NodeAddrError)?;
        address = address.with_relay_url(url);
        cursor += len;
    }
    if cursor != bytes.len() || encode_node_addr(&address) != bytes {
        return Err(NodeAddrError);
    }
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(byte: u8) -> PublicKey {
        iroh::SecretKey::from_bytes(&[byte; 32]).public()
    }

    fn sample() -> EndpointAddr {
        let id = key(0x5A);
        EndpointAddr::new(id)
            .with_ip_addr("127.0.0.1:4242".parse().unwrap())
            .with_ip_addr("[::1]:9999".parse().unwrap())
            .with_relay_url(RelayUrl::from_str("https://relay.example").unwrap())
    }

    #[test]
    fn node_addr_round_trips() {
        let decoded = decode_node_addr(&encode_node_addr(&sample())).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn encode_is_deterministic() {
        assert_eq!(encode_node_addr(&sample()), encode_node_addr(&sample()));
    }

    #[test]
    fn bare_node_id_round_trips() {
        let address = EndpointAddr::new(key(0x11));
        assert_eq!(
            decode_node_addr(&encode_node_addr(&address)).unwrap(),
            address
        );
    }

    #[test]
    fn decode_rejects_truncation_and_trailing_bytes() {
        let encoded = encode_node_addr(&sample());
        assert!(decode_node_addr(&encoded[..encoded.len() - 1]).is_err());
        let mut padded = encoded.clone();
        padded.push(0x00);
        assert!(decode_node_addr(&padded).is_err());
        assert!(decode_node_addr(&[vec![0x02], vec![0x5A; 32]].concat()).is_err());
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut bytes = encode_node_addr(&sample());
        bytes[0] = 0x99;
        assert!(decode_node_addr(&bytes).is_err());
    }

    #[test]
    fn decode_rejects_non_canonical_spellings() {
        // Two identical ip addresses: the set collapses them on decode,
        // so the bytes re-encode differently and are not canonical.
        let id = key(0x77);
        let mut bytes = vec![NODE_ADDR_VERSION];
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        for _ in 0..2 {
            bytes.push(0x04);
            bytes.extend_from_slice(&[127, 0, 0, 1]);
            bytes.extend_from_slice(&4242u16.to_le_bytes());
        }
        bytes.extend_from_slice(&0u32.to_le_bytes());
        assert!(decode_node_addr(&bytes).is_err());

        // Same for a repeated relay url.
        let mut bytes = vec![NODE_ADDR_VERSION];
        bytes.extend_from_slice(id.as_bytes());
        bytes.extend_from_slice(&0u32.to_le_bytes());
        bytes.extend_from_slice(&2u32.to_le_bytes());
        let url = "https://relay.example";
        for _ in 0..2 {
            bytes.extend_from_slice(&(url.len() as u32).to_le_bytes());
            bytes.extend_from_slice(url.as_bytes());
        }
        assert!(decode_node_addr(&bytes).is_err());
    }
}
