//! TLS ClientHello SNI extraction.
//!
//! Parses a TLS record to find the Server Name Indication (SNI)
//! extension in a ClientHello handshake message. This lets mikebom
//! correlate encrypted connections with their destination hostnames
//! before any HTTP data is available.
//!
//! This parser handles the minimum subset of the TLS specification
//! needed for SNI extraction:
//! - TLS record layer (content type 0x16 = Handshake)
//! - Handshake header (type 0x01 = ClientHello)
//! - ClientHello fields (version, random, session ID, cipher suites, compression)
//! - Extensions parsing to find type 0x0000 (server_name)

/// Extract the SNI hostname from a TLS ClientHello record.
///
/// Returns `Some(hostname)` if a valid SNI extension was found,
/// `None` otherwise. The input should be the raw bytes from the
/// start of a TLS connection (the ClientHello record).
pub fn extract_sni(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);

    // ── TLS Record Header ────────────────────────────────
    // ContentType (1 byte): must be 0x16 (Handshake)
    let content_type = cursor.read_u8()?;
    if content_type != 0x16 {
        return None;
    }

    // ProtocolVersion (2 bytes): e.g., 0x0301 for TLS 1.0
    let _version_major = cursor.read_u8()?;
    let _version_minor = cursor.read_u8()?;

    // Length (2 bytes): length of the handshake payload
    let _record_length = cursor.read_u16()?;

    // ── Handshake Header ─────────────────────────────────
    // HandshakeType (1 byte): must be 0x01 (ClientHello)
    let handshake_type = cursor.read_u8()?;
    if handshake_type != 0x01 {
        return None;
    }

    // Length (3 bytes, big-endian 24-bit)
    let _handshake_length = cursor.read_u24()?;

    // ── ClientHello Body ─────────────────────────────────
    // ProtocolVersion (2 bytes)
    let _client_major = cursor.read_u8()?;
    let _client_minor = cursor.read_u8()?;

    // Random (32 bytes)
    cursor.skip(32)?;

    // Session ID (variable length, 1-byte length prefix)
    let session_id_len = cursor.read_u8()? as usize;
    cursor.skip(session_id_len)?;

    // Cipher Suites (variable length, 2-byte length prefix)
    let cipher_suites_len = cursor.read_u16()? as usize;
    cursor.skip(cipher_suites_len)?;

    // Compression Methods (variable length, 1-byte length prefix)
    let compression_len = cursor.read_u8()? as usize;
    cursor.skip(compression_len)?;

    // ── Extensions ───────────────────────────────────────
    // Extensions length (2 bytes)
    let extensions_length = cursor.read_u16()? as usize;
    let extensions_end = cursor.pos + extensions_length;

    while cursor.pos + 4 <= extensions_end {
        let ext_type = cursor.read_u16()?;
        let ext_len = cursor.read_u16()? as usize;

        if ext_type == 0x0000 {
            // SNI extension found — parse server_name_list
            return parse_sni_extension(&cursor.data[cursor.pos..cursor.pos + ext_len]);
        }

        cursor.skip(ext_len)?;
    }

    None
}

/// Parse the SNI extension payload to extract the hostname.
///
/// Extension data format:
///   ServerNameList length (2 bytes)
///   For each entry:
///     NameType (1 byte): 0x00 = host_name
///     HostName length (2 bytes)
///     HostName (variable)
fn parse_sni_extension(data: &[u8]) -> Option<String> {
    let mut cursor = Cursor::new(data);

    // ServerNameList length
    let _list_len = cursor.read_u16()?;

    // We only need the first host_name entry.
    let name_type = cursor.read_u8()?;
    if name_type != 0x00 {
        return None;
    }

    let name_len = cursor.read_u16()? as usize;
    let name_bytes = cursor.read_bytes(name_len)?;

    // The hostname must be valid UTF-8 (it is always ASCII in practice).
    let hostname = std::str::from_utf8(name_bytes).ok()?;

    // Basic sanity check: hostname should contain at least one dot
    // and no control characters.
    if hostname.is_empty()
        || hostname.bytes().any(|b| b < 0x20)
    {
        return None;
    }

    Some(hostname.to_string())
}

/// A simple cursor for reading big-endian binary data.
struct Cursor<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }

    fn read_u8(&mut self) -> Option<u8> {
        if self.pos >= self.data.len() {
            return None;
        }
        let val = self.data[self.pos];
        self.pos += 1;
        Some(val)
    }

    fn read_u16(&mut self) -> Option<u16> {
        if self.pos + 2 > self.data.len() {
            return None;
        }
        let val = u16::from_be_bytes([self.data[self.pos], self.data[self.pos + 1]]);
        self.pos += 2;
        Some(val)
    }

    fn read_u24(&mut self) -> Option<u32> {
        if self.pos + 3 > self.data.len() {
            return None;
        }
        let val = (self.data[self.pos] as u32) << 16
            | (self.data[self.pos + 1] as u32) << 8
            | (self.data[self.pos + 2] as u32);
        self.pos += 3;
        Some(val)
    }

    fn read_bytes(&mut self, len: usize) -> Option<&'a [u8]> {
        if self.pos + len > self.data.len() {
            return None;
        }
        let slice = &self.data[self.pos..self.pos + len];
        self.pos += len;
        Some(slice)
    }

    fn skip(&mut self, n: usize) -> Option<()> {
        if self.pos + n > self.data.len() {
            return None;
        }
        self.pos += n;
        Some(())
    }
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    /// Build a minimal but valid TLS ClientHello with the given SNI hostname.
    fn build_client_hello(hostname: &str) -> Vec<u8> {
        let name_bytes = hostname.as_bytes();

        // SNI extension payload:
        //   name_type(1) + name_length(2) + name(N)
        let sni_entry_len = 1 + 2 + name_bytes.len();
        // server_name_list_length(2) + entries
        let sni_ext_data_len = 2 + sni_entry_len;
        // ext_type(2) + ext_length(2) + ext_data
        let sni_ext_total = 2 + 2 + sni_ext_data_len;

        // Extensions block: extensions_length(2) + sni extension
        let extensions_total = 2 + sni_ext_total;

        // ClientHello body:
        //   version(2) + random(32) + session_id_len(1) + session_id(0)
        //   + cipher_suites_len(2) + cipher_suites(2) -- one dummy suite
        //   + compression_len(1) + compression(1) -- null compression
        //   + extensions
        let client_hello_body_len = 2 + 32 + 1 + 0 + 2 + 2 + 1 + 1 + extensions_total;

        // Handshake header: type(1) + length(3) + body
        let handshake_total = 1 + 3 + client_hello_body_len;

        // TLS record: content_type(1) + version(2) + length(2) + handshake
        let mut buf = Vec::with_capacity(5 + handshake_total);

        // TLS Record Header
        buf.push(0x16); // ContentType: Handshake
        buf.push(0x03); // Version major
        buf.push(0x01); // Version minor (TLS 1.0)
        buf.extend_from_slice(&(handshake_total as u16).to_be_bytes());

        // Handshake Header
        buf.push(0x01); // ClientHello
        // 24-bit length
        buf.push(((client_hello_body_len >> 16) & 0xFF) as u8);
        buf.push(((client_hello_body_len >> 8) & 0xFF) as u8);
        buf.push((client_hello_body_len & 0xFF) as u8);

        // ClientHello: version
        buf.push(0x03);
        buf.push(0x03); // TLS 1.2

        // ClientHello: random (32 bytes of zeros for test)
        buf.extend_from_slice(&[0u8; 32]);

        // Session ID: length 0
        buf.push(0x00);

        // Cipher suites: length 2, one dummy suite
        buf.extend_from_slice(&[0x00, 0x02]); // length
        buf.extend_from_slice(&[0x00, 0x2F]); // TLS_RSA_WITH_AES_128_CBC_SHA

        // Compression methods: length 1, null
        buf.push(0x01);
        buf.push(0x00);

        // Extensions length
        buf.extend_from_slice(&(sni_ext_total as u16).to_be_bytes());

        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]); // extension type: server_name
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&(sni_entry_len as u16).to_be_bytes()); // server_name_list length
        buf.push(0x00); // name_type: host_name
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        buf
    }

    #[test]
    fn extract_sni_simple() {
        let hello = build_client_hello("registry.npmjs.org");
        let sni = extract_sni(&hello).expect("should extract SNI");
        assert_eq!(sni, "registry.npmjs.org");
    }

    #[test]
    fn extract_sni_github() {
        let hello = build_client_hello("github.com");
        let sni = extract_sni(&hello).expect("should extract SNI");
        assert_eq!(sni, "github.com");
    }

    #[test]
    fn extract_sni_subdomain() {
        let hello = build_client_hello("dl-cdn.alpinelinux.org");
        let sni = extract_sni(&hello).expect("should extract SNI");
        assert_eq!(sni, "dl-cdn.alpinelinux.org");
    }

    #[test]
    fn extract_sni_returns_none_for_non_tls() {
        let data = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        assert!(extract_sni(data).is_none());
    }

    #[test]
    fn extract_sni_returns_none_for_short_data() {
        let data = &[0x16, 0x03, 0x01];
        assert!(extract_sni(data).is_none());
    }

    #[test]
    fn extract_sni_returns_none_for_server_hello() {
        // ContentType 0x16 (Handshake) but HandshakeType 0x02 (ServerHello)
        let mut hello = build_client_hello("example.com");
        // Offset 5 is the handshake type byte
        hello[5] = 0x02;
        assert!(extract_sni(&hello).is_none());
    }

    #[test]
    fn extract_sni_returns_none_for_empty() {
        assert!(extract_sni(&[]).is_none());
    }

    /// A real-world captured TLS 1.2 ClientHello from curl to pypi.org.
    /// This is a manually constructed byte sequence matching a real capture.
    #[test]
    fn extract_sni_real_world_style() {
        // Build a realistic ClientHello with additional extensions before SNI.
        let hostname = "pypi.org";
        let name_bytes = hostname.as_bytes();

        let sni_entry_len = 1 + 2 + name_bytes.len();
        let sni_ext_data_len = 2 + sni_entry_len;

        // Add a dummy extension (supported_versions, type 0x002b) before SNI.
        let dummy_ext_data = [0x03, 0x03, 0x04]; // 3 bytes of data
        let dummy_ext_total = 2 + 2 + dummy_ext_data.len(); // type + len + data

        let sni_ext_total = 2 + 2 + sni_ext_data_len;
        let extensions_total = 2 + dummy_ext_total + sni_ext_total;

        let client_hello_body_len = 2 + 32 + 1 + 32 + 2 + 4 + 1 + 1 + extensions_total;
        // 32 bytes session ID this time, 4 bytes cipher suites (2 suites)
        let handshake_total = 1 + 3 + client_hello_body_len;

        let mut buf = Vec::new();

        // TLS Record Header
        buf.push(0x16);
        buf.push(0x03);
        buf.push(0x01);
        buf.extend_from_slice(&(handshake_total as u16).to_be_bytes());

        // Handshake Header
        buf.push(0x01);
        buf.push(((client_hello_body_len >> 16) & 0xFF) as u8);
        buf.push(((client_hello_body_len >> 8) & 0xFF) as u8);
        buf.push((client_hello_body_len & 0xFF) as u8);

        // ClientHello version
        buf.push(0x03);
        buf.push(0x03);

        // Random (32 bytes)
        buf.extend_from_slice(&[0xAB; 32]);

        // Session ID: 32 bytes
        buf.push(0x20); // length = 32
        buf.extend_from_slice(&[0xCD; 32]);

        // Cipher suites: 2 suites = 4 bytes
        buf.extend_from_slice(&[0x00, 0x04]);
        buf.extend_from_slice(&[0x13, 0x01]); // TLS_AES_128_GCM_SHA256
        buf.extend_from_slice(&[0x13, 0x02]); // TLS_AES_256_GCM_SHA384

        // Compression: null only
        buf.push(0x01);
        buf.push(0x00);

        // Extensions length
        let ext_len = dummy_ext_total + sni_ext_total;
        buf.extend_from_slice(&(ext_len as u16).to_be_bytes());

        // Dummy extension (supported_versions)
        buf.extend_from_slice(&[0x00, 0x2b]); // type
        buf.extend_from_slice(&(dummy_ext_data.len() as u16).to_be_bytes());
        buf.extend_from_slice(&dummy_ext_data);

        // SNI extension
        buf.extend_from_slice(&[0x00, 0x00]); // type: server_name
        buf.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
        buf.extend_from_slice(&(sni_entry_len as u16).to_be_bytes());
        buf.push(0x00); // host_name
        buf.extend_from_slice(&(name_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(name_bytes);

        let sni = extract_sni(&buf).expect("should extract SNI from realistic ClientHello");
        assert_eq!(sni, "pypi.org");
    }
}
