//! Private v1 credential-agent protocol. Frames and secrets are never logged.
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::Sha256;
use std::io;
use tokio::io::{AsyncRead, AsyncReadExt};

pub const VERSION: u8 = 1;
pub const MAX_FRAME: usize = 16 * 1024;
pub const MAX_HEADERS: usize = 16;
pub const MAX_VALUE: usize = 4096;
pub type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Request {
    pub version: u8,
    pub operation: Operation,
    pub profile: String,
    pub audience: String,
    pub nonce: String,
    pub mac: String,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Operation {
    Ping,
    Acquire,
    UnauthorizedRecovery,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct Response {
    pub version: u8,
    pub ok: bool,
    pub nonce: String,
    pub mac: String,
    #[serde(default)]
    pub headers: Vec<(String, String)>,
}

pub fn encode<T: Serialize>(value: &T) -> Result<Vec<u8>, serde_json::Error> {
    let mut out = serde_json::to_vec(value)?;
    out.push(b'\n');
    if out.len() > MAX_FRAME {
        return Err(<serde_json::Error as serde::ser::Error>::custom(
            "frame too large",
        ));
    }
    Ok(out)
}
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(MAX_FRAME);
    loop {
        let byte = reader.read_u8().await?;
        out.push(byte);
        if out.len() > MAX_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "frame too large",
            ));
        }
        if byte == b'\n' {
            return Ok(out);
        }
    }
}
pub fn decode<T: DeserializeOwned>(frame: &[u8]) -> Result<T, serde_json::Error> {
    if frame.len() > MAX_FRAME || !frame.ends_with(b"\n") {
        return Err(<serde_json::Error as serde::de::Error>::custom(
            "invalid frame",
        ));
    }
    serde_json::from_slice(&frame[..frame.len() - 1])
}
pub fn validate_request(r: &Request, profile: &str, audience: &str) -> bool {
    r.version == VERSION
        && r.profile == profile
        && r.audience == audience
        && r.nonce.len() == 64
        && r.mac.len() == 64
        && r.profile.len() <= 128
        && r.audience.len() <= 256
}
pub fn request_mac(secret: &[u8], r: &Request) -> String {
    mac(
        secret,
        format!(
            "request\0{}\0{}\0{}\0{}\0{}",
            r.version,
            serde_json::to_string(&r.operation).unwrap_or_default(),
            r.profile,
            r.audience,
            r.nonce
        )
        .as_bytes(),
    )
}
pub fn response_mac(secret: &[u8], r: &Response) -> String {
    mac(
        secret,
        format!(
            "response\0{}\0{}\0{}\0{}",
            r.version,
            r.ok,
            r.nonce,
            serde_json::to_string(&r.headers).unwrap_or_default()
        )
        .as_bytes(),
    )
}
fn mac(secret: &[u8], data: &[u8]) -> String {
    let mut h = HmacSha256::new_from_slice(secret).expect("HMAC accepts all key lengths");
    h.update(data);
    hex::encode(h.finalize().into_bytes())
}
pub fn valid_mac(expected: &str, actual: &str) -> bool {
    expected.len() == actual.len()
        && subtle::ConstantTimeEq::ct_eq(expected.as_bytes(), actual.as_bytes()).into()
}
pub fn validate_response(r: &Response, nonce: &str) -> bool {
    r.version == VERSION
        && r.nonce == nonce
        && r.headers.len() <= MAX_HEADERS
        && r.headers
            .iter()
            .all(|(n, v)| n.len() <= 128 && v.len() <= MAX_VALUE)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn oversized_unterminated_frame_is_rejected_without_unbounded_read() {
        let mut input = tokio::io::repeat(b'x').take((MAX_FRAME + 1) as u64);
        assert!(read_frame(&mut input).await.is_err());
    }
    #[test]
    fn auth_rejects_wrong_nonce_or_mac() {
        let r = Request {
            version: VERSION,
            operation: Operation::Ping,
            profile: "codex".into(),
            audience: "codex".into(),
            nonce: "a".repeat(64),
            mac: "0".repeat(64),
        };
        assert!(!validate_request(&r, "codex", "codex") || !valid_mac("1", "2"));
    }
    #[test]
    fn request_validation_rejects_each_identity_mismatch() {
        let base = Request {
            version: VERSION,
            operation: Operation::Acquire,
            profile: "codex".into(),
            audience: "codex".into(),
            nonce: "a".repeat(64),
            mac: "b".repeat(64),
        };
        let mut invalid = vec![];
        let mut request = base.clone();
        request.version = VERSION + 1;
        invalid.push(request);
        let mut request = base.clone();
        request.profile = "other".into();
        invalid.push(request);
        let mut request = base.clone();
        request.audience = "other".into();
        invalid.push(request);
        let mut request = base.clone();
        request.nonce = "short".into();
        invalid.push(request);
        let mut request = base.clone();
        request.mac = "short".into();
        invalid.push(request);
        for request in invalid {
            assert!(!validate_request(&request, "codex", "codex"));
        }
    }
    #[test]
    fn response_validation_enforces_bounds() {
        let mut response = Response {
            version: VERSION,
            ok: true,
            nonce: "a".repeat(64),
            mac: String::new(),
            headers: vec![("authorization".into(), "token".into())],
        };
        assert!(validate_response(&response, &response.nonce));
        response.headers = vec![("x".into(), String::new()); MAX_HEADERS + 1];
        assert!(!validate_response(&response, &response.nonce));
        response.headers = vec![("x".into(), "x".repeat(MAX_VALUE + 1))];
        assert!(!validate_response(&response, &response.nonce));
    }
    #[test]
    fn frames_are_newline_delimited_and_bounded() {
        let request = Request {
            version: VERSION,
            operation: Operation::Ping,
            profile: "codex".into(),
            audience: "codex".into(),
            nonce: "a".repeat(64),
            mac: "b".repeat(64),
        };
        let frame = encode(&request).unwrap();
        assert_eq!(decode::<Request>(&frame).unwrap(), request);
        assert!(decode::<Request>(&frame[..frame.len() - 1]).is_err());
        assert!(!valid_mac("a", "b"));
    }
}
