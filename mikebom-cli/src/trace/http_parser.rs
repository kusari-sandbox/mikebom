//! HTTP request/response parser for TLS plaintext fragments.
//!
//! After eBPF captures the plaintext from `SSL_read`/`SSL_write`, this
//! module extracts HTTP metadata from the first bytes of each payload.
//! It is intentionally simple — we only need the request line, Host
//! header, status line, and Content-Length for attestation purposes.

use mikebom_common::attestation::network::{HttpRequest, HttpResponse};

/// Parse an HTTP request from a plaintext TLS fragment.
///
/// Extracts the method, path, and Host header from the first line
/// and headers of the payload. Returns `None` if the fragment does
/// not look like an HTTP request.
pub fn parse_request(payload: &[u8]) -> Option<HttpRequest> {
    let text = std::str::from_utf8(payload).ok()?;

    // The request line is the first line: "METHOD PATH HTTP/x.y\r\n"
    let request_line = text.lines().next()?;
    let mut parts = request_line.split_whitespace();

    let method = parts.next()?;
    let path = parts.next()?;
    let version = parts.next().unwrap_or("");

    // Validate that this looks like an HTTP method.
    if !is_http_method(method) {
        return None;
    }

    // Validate version prefix.
    if !version.is_empty() && !version.starts_with("HTTP/") {
        return None;
    }

    // Extract Host header.
    let host_header = extract_header(text, "Host");

    Some(HttpRequest {
        method: method.to_string(),
        path: path.to_string(),
        host_header,
    })
}

/// Parse an HTTP response from a plaintext TLS fragment.
///
/// Extracts the status code and Content-Length header. Returns `None`
/// if the fragment does not look like an HTTP response.
pub fn parse_response(payload: &[u8]) -> Option<HttpResponse> {
    let text = std::str::from_utf8(payload).ok()?;

    // Status line: "HTTP/x.y STATUS REASON\r\n"
    let status_line = text.lines().next()?;
    let mut parts = status_line.split_whitespace();

    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }

    let status_str = parts.next()?;
    let status_code: u16 = status_str.parse().ok()?;

    // Validate status code range.
    if !(100..=599).contains(&status_code) {
        return None;
    }

    // Extract Content-Length header.
    let content_length = extract_header(text, "Content-Length")
        .and_then(|v| v.parse::<u64>().ok());

    Some(HttpResponse {
        status_code,
        content_length,
        content_hash: None,
    })
}

/// Check whether a string is a recognized HTTP method.
fn is_http_method(s: &str) -> bool {
    matches!(
        s,
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH"
    )
}

/// Extract the value of a header by name (case-insensitive).
///
/// Scans through header lines looking for `name: value`. Returns the
/// trimmed value if found.
fn extract_header(text: &str, name: &str) -> Option<String> {
    let name_lower = name.to_ascii_lowercase();
    for line in text.lines().skip(1) {
        // Empty line signals end of headers.
        if line.is_empty() || line == "\r" {
            break;
        }
        if let Some((key, value)) = line.split_once(':') {
            if key.trim().to_ascii_lowercase() == name_lower {
                return Some(value.trim().to_string());
            }
        }
    }
    None
}

#[cfg(test)]
#[cfg_attr(test, allow(clippy::unwrap_used))]
mod tests {
    use super::*;

    #[test]
    fn parse_get_request() {
        let payload = b"GET /packages/sha256/abc123 HTTP/1.1\r\nHost: registry.npmjs.org\r\nUser-Agent: npm/9.0\r\nAccept: */*\r\n\r\n";
        let req = parse_request(payload).expect("should parse GET request");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/packages/sha256/abc123");
        assert_eq!(req.host_header.as_deref(), Some("registry.npmjs.org"));
    }

    #[test]
    fn parse_post_request() {
        let payload = b"POST /api/v2/upload HTTP/1.1\r\nHost: uploads.example.com\r\nContent-Type: application/octet-stream\r\nContent-Length: 4096\r\n\r\n";
        let req = parse_request(payload).expect("should parse POST request");
        assert_eq!(req.method, "POST");
        assert_eq!(req.path, "/api/v2/upload");
        assert_eq!(req.host_header.as_deref(), Some("uploads.example.com"));
    }

    #[test]
    fn parse_request_no_host() {
        let payload = b"GET / HTTP/1.0\r\nAccept: text/html\r\n\r\n";
        let req = parse_request(payload).expect("should parse request without Host");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/");
        assert!(req.host_header.is_none());
    }

    #[test]
    fn parse_request_rejects_non_http() {
        let payload = b"This is not an HTTP request\r\n";
        assert!(parse_request(payload).is_none());
    }

    #[test]
    fn parse_request_rejects_binary() {
        let payload: &[u8] = &[0x16, 0x03, 0x01, 0x00, 0xff, 0x01];
        assert!(parse_request(payload).is_none());
    }

    #[test]
    fn parse_200_response() {
        let payload = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1234\r\n\r\n{\"key\":\"value\"}";
        let resp = parse_response(payload).expect("should parse 200 response");
        assert_eq!(resp.status_code, 200);
        assert_eq!(resp.content_length, Some(1234));
        assert!(resp.content_hash.is_none());
    }

    #[test]
    fn parse_301_redirect() {
        let payload = b"HTTP/1.1 301 Moved Permanently\r\nLocation: https://new.example.com/path\r\n\r\n";
        let resp = parse_response(payload).expect("should parse 301 response");
        assert_eq!(resp.status_code, 301);
        assert!(resp.content_length.is_none());
    }

    #[test]
    fn parse_404_response() {
        let payload = b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n";
        let resp = parse_response(payload).expect("should parse 404 response");
        assert_eq!(resp.status_code, 404);
        assert_eq!(resp.content_length, Some(0));
    }

    #[test]
    fn parse_response_rejects_non_http() {
        let payload = b"Not an HTTP response at all\r\n";
        assert!(parse_response(payload).is_none());
    }

    #[test]
    fn parse_response_rejects_invalid_status() {
        let payload = b"HTTP/1.1 abc OK\r\n\r\n";
        assert!(parse_response(payload).is_none());
    }

    #[test]
    fn header_extraction_case_insensitive() {
        let payload = b"GET / HTTP/1.1\r\nhost: EXAMPLE.COM\r\n\r\n";
        let req = parse_request(payload).expect("should parse with lowercase host");
        assert_eq!(req.host_header.as_deref(), Some("EXAMPLE.COM"));
    }

    #[test]
    fn parse_http2_style_path() {
        let payload = b"GET /v2/library/alpine/manifests/latest HTTP/2\r\nHost: registry-1.docker.io\r\nAuthorization: Bearer token123\r\n\r\n";
        let req = parse_request(payload).expect("should parse request with HTTP/2");
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/v2/library/alpine/manifests/latest");
        assert_eq!(req.host_header.as_deref(), Some("registry-1.docker.io"));
    }
}
