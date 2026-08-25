use thiserror::Error;

const TLS_HANDSHAKE: u8 = 22;
const CLIENT_HELLO: u8 = 1;
const SERVER_NAME_EXTENSION: u16 = 0;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classification {
    PlainHttp,
    Tls { sni: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseProgress {
    NeedMore,
    Complete(Classification),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("invalid TLS ClientHello: {0}")]
    Invalid(&'static str),
}

/// Incremental TLS/HTTP classifier.
///
/// Each input byte is deframed at most once.  Only the first handshake is
/// retained, and bytes after the declared ClientHello length are skipped.
/// This is important for the public listener: re-running classification over a
/// growing prefix would otherwise make fragmented hellos quadratic and would
/// allocate/copy the TLS records on every read.
pub struct Classifier {
    state: ClassifierState,
}

enum ClassifierState {
    DetectHttp { prefix: [u8; 8], prefix_len: usize },
    Tls(TlsDeframer),
    Complete,
}

struct TlsDeframer {
    record_header: [u8; 5],
    record_header_len: usize,
    record_payload_remaining: usize,
    handshake: Vec<u8>,
    handshake_total_len: Option<usize>,
}

impl Default for Classifier {
    fn default() -> Self {
        Self::new()
    }
}

impl Classifier {
    pub fn new() -> Self {
        Self {
            state: ClassifierState::DetectHttp {
                prefix: [0; 8],
                prefix_len: 0,
            },
        }
    }

    pub fn push(&mut self, input: &[u8]) -> Result<ParseProgress, ParseError> {
        match &mut self.state {
            ClassifierState::DetectHttp { .. } => self.detect_protocol(input),
            ClassifierState::Tls(deframer) => {
                let progress = deframer.push(input)?;
                if matches!(progress, ParseProgress::Complete(_)) {
                    self.state = ClassifierState::Complete;
                }
                Ok(progress)
            }
            ClassifierState::Complete => Err(ParseError::Invalid("classifier already completed")),
        }
    }

    fn detect_protocol(&mut self, input: &[u8]) -> Result<ParseProgress, ParseError> {
        let ClassifierState::DetectHttp { prefix, prefix_len } = &mut self.state else {
            unreachable!();
        };
        if input.is_empty() {
            return Ok(ParseProgress::NeedMore);
        }

        // A TLS record is unambiguous from its first byte, so it can enter the
        // deframer without accumulating or replaying an HTTP-sized prefix.
        if *prefix_len == 0 && input[0] == TLS_HANDSHAKE {
            let mut deframer = TlsDeframer::new();
            let progress = deframer.push(input)?;
            self.state = if matches!(progress, ParseProgress::Complete(_)) {
                ClassifierState::Complete
            } else {
                ClassifierState::Tls(deframer)
            };
            return Ok(progress);
        }

        let copied = input.len().min(prefix.len() - *prefix_len);
        prefix[*prefix_len..*prefix_len + copied].copy_from_slice(&input[..copied]);
        *prefix_len += copied;
        let candidate = &prefix[..*prefix_len];
        if looks_like_http(candidate) {
            self.state = ClassifierState::Complete;
            return Ok(ParseProgress::Complete(Classification::PlainHttp));
        }
        if *prefix_len < prefix.len() && could_be_http_prefix(candidate) {
            return Ok(ParseProgress::NeedMore);
        }
        Err(ParseError::Invalid("neither TLS nor supported plain HTTP"))
    }
}

impl TlsDeframer {
    fn new() -> Self {
        Self {
            record_header: [0; 5],
            record_header_len: 0,
            record_payload_remaining: 0,
            handshake: Vec::new(),
            handshake_total_len: None,
        }
    }

    fn push(&mut self, mut input: &[u8]) -> Result<ParseProgress, ParseError> {
        while !input.is_empty() {
            if self.record_header_len < self.record_header.len() {
                let copied = input
                    .len()
                    .min(self.record_header.len() - self.record_header_len);
                self.record_header[self.record_header_len..self.record_header_len + copied]
                    .copy_from_slice(&input[..copied]);
                self.record_header_len += copied;
                input = &input[copied..];
                if self.record_header_len < self.record_header.len() {
                    return Ok(ParseProgress::NeedMore);
                }
                self.record_payload_remaining = validate_record_header(&self.record_header)?;
            }

            let consumed = input.len().min(self.record_payload_remaining);
            self.append_handshake(&input[..consumed]);
            self.record_payload_remaining -= consumed;
            input = &input[consumed..];
            if self.record_payload_remaining != 0 {
                return Ok(ParseProgress::NeedMore);
            }

            // Match the previous parser's record-boundary semantics: a
            // ClientHello is classified only once the record containing its
            // final byte has arrived in full.
            if self.handshake.len() >= 4 {
                if self.handshake[0] != CLIENT_HELLO {
                    return Err(ParseError::Invalid("first handshake is not ClientHello"));
                }
                let total = self.handshake_total_len.expect("length set at four bytes");
                if total == 4 {
                    return Err(ParseError::Invalid("empty ClientHello"));
                }
                if self.handshake.len() == total {
                    let sni = parse_client_hello(&self.handshake[4..])?;
                    return Ok(ParseProgress::Complete(Classification::Tls { sni }));
                }
            }

            self.record_header_len = 0;
        }
        Ok(ParseProgress::NeedMore)
    }

    fn append_handshake(&mut self, mut payload: &[u8]) {
        if self.handshake.len() < 4 {
            let copied = payload.len().min(4 - self.handshake.len());
            self.handshake.extend_from_slice(&payload[..copied]);
            payload = &payload[copied..];
            if self.handshake.len() == 4 {
                let body_len = ((self.handshake[1] as usize) << 16)
                    | ((self.handshake[2] as usize) << 8)
                    | self.handshake[3] as usize;
                self.handshake_total_len = Some(body_len + 4);
            }
        }
        let Some(total) = self.handshake_total_len else {
            return;
        };
        let copied = payload
            .len()
            .min(total.saturating_sub(self.handshake.len()));
        // For the common one-record ClientHello this makes the handshake a
        // single allocation. Fragmented input remains amortized linear.
        self.handshake.reserve(copied);
        self.handshake.extend_from_slice(&payload[..copied]);
    }
}

#[cfg(test)]
fn classify(buffer: &[u8]) -> Result<ParseProgress, ParseError> {
    Classifier::new().push(buffer)
}

fn validate_record_header(header: &[u8; 5]) -> Result<usize, ParseError> {
    if header[0] != TLS_HANDSHAKE {
        return Err(ParseError::Invalid("unexpected TLS record type"));
    }
    if header[1] != 3 || !(1..=4).contains(&header[2]) {
        return Err(ParseError::Invalid("unsupported TLS record version"));
    }
    let record_len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if record_len == 0 || record_len > 16_384 + 2_048 {
        return Err(ParseError::Invalid("invalid TLS record length"));
    }
    Ok(record_len)
}

fn looks_like_http(buffer: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| buffer.starts_with(method))
}

fn could_be_http_prefix(buffer: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"HEAD ",
        b"POST ",
        b"PUT ",
        b"DELETE ",
        b"OPTIONS ",
        b"PATCH ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| method.starts_with(buffer))
}

fn parse_client_hello(hello: &[u8]) -> Result<Option<String>, ParseError> {
    let mut cursor = 0usize;
    take(hello, &mut cursor, 2 + 32)?;
    let session_id_len = take(hello, &mut cursor, 1)?[0] as usize;
    take(hello, &mut cursor, session_id_len)?;
    let cipher_len = read_u16(hello, &mut cursor)? as usize;
    // Bit parity keeps this compatible with Rust 1.85, where
    // usize::is_multiple_of is not stable yet.
    if cipher_len < 2 || cipher_len & 1 != 0 {
        return Err(ParseError::Invalid("invalid cipher suite vector"));
    }
    take(hello, &mut cursor, cipher_len)?;
    let compression_len = take(hello, &mut cursor, 1)?[0] as usize;
    if compression_len == 0 {
        return Err(ParseError::Invalid("empty compression vector"));
    }
    take(hello, &mut cursor, compression_len)?;
    if cursor == hello.len() {
        return Ok(None);
    }
    let extensions_len = read_u16(hello, &mut cursor)? as usize;
    let extensions = take(hello, &mut cursor, extensions_len)?;
    if cursor != hello.len() {
        return Err(ParseError::Invalid("trailing ClientHello bytes"));
    }

    let mut ext_cursor = 0usize;
    while ext_cursor < extensions.len() {
        let extension_type = read_u16(extensions, &mut ext_cursor)?;
        let extension_len = read_u16(extensions, &mut ext_cursor)? as usize;
        let extension = take(extensions, &mut ext_cursor, extension_len)?;
        if extension_type != SERVER_NAME_EXTENSION {
            continue;
        }
        let mut name_cursor = 0usize;
        let name_list_len = read_u16(extension, &mut name_cursor)? as usize;
        let names = take(extension, &mut name_cursor, name_list_len)?;
        if name_cursor != extension.len() {
            return Err(ParseError::Invalid("trailing SNI extension bytes"));
        }
        let mut cursor = 0usize;
        while cursor < names.len() {
            let name_type = take(names, &mut cursor, 1)?[0];
            let name_len = read_u16(names, &mut cursor)? as usize;
            let name = take(names, &mut cursor, name_len)?;
            if name_type == 0 {
                let name = std::str::from_utf8(name)
                    .map_err(|_| ParseError::Invalid("SNI hostname is not UTF-8"))?;
                return Ok(Some(normalize_sni(name)?));
            }
        }
        return Ok(None);
    }
    Ok(None)
}

fn normalize_sni(value: &str) -> Result<String, ParseError> {
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return Err(ParseError::Invalid("invalid SNI hostname"));
    }
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    for label in value.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return Err(ParseError::Invalid("invalid SNI hostname"));
        }
    }
    Ok(value)
}

fn read_u16(input: &[u8], cursor: &mut usize) -> Result<u16, ParseError> {
    let value = take(input, cursor, 2)?;
    Ok(u16::from_be_bytes([value[0], value[1]]))
}

fn take<'a>(input: &'a [u8], cursor: &mut usize, len: usize) -> Result<&'a [u8], ParseError> {
    let end = cursor
        .checked_add(len)
        .ok_or(ParseError::Invalid("length overflow"))?;
    let value = input
        .get(*cursor..end)
        .ok_or(ParseError::Invalid("truncated ClientHello field"))?;
    *cursor = end;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hello(hostname: Option<&str>, split_at: Option<usize>) -> Vec<u8> {
        let mut body = vec![3, 3];
        body.extend([7; 32]);
        body.push(0);
        body.extend([0, 2, 0x13, 1]);
        body.extend([1, 0]);
        if let Some(hostname) = hostname {
            let name = hostname.as_bytes();
            let mut extension = Vec::new();
            extension.extend(((name.len() + 3) as u16).to_be_bytes());
            extension.push(0);
            extension.extend((name.len() as u16).to_be_bytes());
            extension.extend(name);
            let mut extensions = Vec::new();
            extensions.extend(SERVER_NAME_EXTENSION.to_be_bytes());
            extensions.extend((extension.len() as u16).to_be_bytes());
            extensions.extend(extension);
            body.extend((extensions.len() as u16).to_be_bytes());
            body.extend(extensions);
        }
        let mut handshake = vec![CLIENT_HELLO];
        let len = body.len();
        handshake.extend([(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        handshake.extend(body);

        let at = split_at.unwrap_or(handshake.len()).min(handshake.len());
        let mut records = Vec::new();
        for chunk in [&handshake[..at], &handshake[at..]] {
            if chunk.is_empty() {
                continue;
            }
            records.extend([TLS_HANDSHAKE, 3, 3]);
            records.extend((chunk.len() as u16).to_be_bytes());
            records.extend(chunk);
        }
        records
    }

    #[test]
    fn parses_fragmented_client_hello() {
        let data = hello(Some("EXAMPLE.Test"), Some(10));
        for prefix in 0..data.len() {
            assert_eq!(classify(&data[..prefix]).unwrap(), ParseProgress::NeedMore);
        }
        assert_eq!(
            classify(&data).unwrap(),
            ParseProgress::Complete(Classification::Tls {
                sni: Some("example.test".to_string())
            })
        );
    }

    #[test]
    fn classifies_http_and_tls_without_sni() {
        assert_eq!(
            classify(b"GET / HTTP/1.1\r\n").unwrap(),
            ParseProgress::Complete(Classification::PlainHttp)
        );
        assert_eq!(
            classify(&hello(None, None)).unwrap(),
            ParseProgress::Complete(Classification::Tls { sni: None })
        );
    }

    #[test]
    fn rejects_invalid_record_lengths() {
        assert!(classify(&[TLS_HANDSHAKE, 3, 3, 0xff, 0xff]).is_err());
    }

    #[test]
    fn incremental_parser_accepts_every_byte_boundary() {
        let data = hello(Some("EXAMPLE.Test"), Some(11));
        for chunk_size in 1..=data.len() {
            let mut parser = Classifier::new();
            let mut progress = ParseProgress::NeedMore;
            for chunk in data.chunks(chunk_size) {
                progress = parser.push(chunk).unwrap();
            }
            assert_eq!(
                progress,
                ParseProgress::Complete(Classification::Tls {
                    sni: Some("example.test".to_string())
                }),
                "chunk size {chunk_size}"
            );
        }
    }

    #[test]
    fn incremental_parser_handles_multi_record_hello_and_suffix() {
        let mut data = hello(Some("example.test"), Some(3));
        data.extend_from_slice(b"already-buffered-application-data");
        let mut parser = Classifier::new();
        assert_eq!(
            parser.push(&data).unwrap(),
            ParseProgress::Complete(Classification::Tls {
                sni: Some("example.test".to_string())
            })
        );
    }

    #[test]
    fn incremental_parser_keeps_fragmented_http_semantics() {
        for request in [
            b"GET / HTTP/1.1\r\n".as_slice(),
            b"CONNECT x:443 HTTP/1.1\r\n",
        ] {
            let mut parser = Classifier::new();
            let mut progress = ParseProgress::NeedMore;
            for byte in request {
                progress = parser.push(std::slice::from_ref(byte)).unwrap();
                if matches!(progress, ParseProgress::Complete(_)) {
                    break;
                }
            }
            assert_eq!(progress, ParseProgress::Complete(Classification::PlainHttp));
        }
    }

    #[test]
    fn incremental_parser_preserves_tls_without_sni() {
        let data = hello(None, Some(1));
        let mut parser = Classifier::new();
        let mut progress = ParseProgress::NeedMore;
        for byte in &data {
            progress = parser.push(std::slice::from_ref(byte)).unwrap();
        }
        assert_eq!(
            progress,
            ParseProgress::Complete(Classification::Tls { sni: None })
        );
    }

    #[test]
    fn incremental_parser_does_not_copy_bytes_after_declared_client_hello() {
        let mut data = hello(Some("example.test"), None);
        // The old parser intentionally waits for the current TLS record to be
        // complete before classifying.  Keep that behavior, while proving the
        // deframer ignores a large record suffix instead of retaining it.
        let declared_record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
        let suffix = vec![0x5a; 8 * 1024];
        data[3..5].copy_from_slice(&((declared_record_len + suffix.len()) as u16).to_be_bytes());
        data.extend_from_slice(&suffix);

        let mut parser = Classifier::new();
        let progress = parser.push(&data).unwrap();
        assert_eq!(
            progress,
            ParseProgress::Complete(Classification::Tls {
                sni: Some("example.test".to_string())
            })
        );
        let ClassifierState::Complete = parser.state else {
            panic!("classifier did not release its TLS deframer after completion");
        };
    }

    #[test]
    fn incremental_parser_rejects_invalid_continuation_record_header() {
        let mut data = hello(Some("example.test"), Some(3));
        // Corrupt the second record type.  Fragment the input so the first
        // push ends exactly before that header.
        let second_header = 5 + 3;
        data[second_header] = 23;
        let mut parser = Classifier::new();
        assert_eq!(
            parser.push(&data[..second_header]).unwrap(),
            ParseProgress::NeedMore
        );
        assert!(parser.push(&data[second_header..]).is_err());
    }
}
