//! Minimal, zero-dependency JSON — value model, serializer, and parser.
//!
//! Just enough for the [`crate::audit`] reports and the `slha-mcp` server: no
//! `serde`, no external crates, one file. The serializer emits **compact
//! single-line** output (required for MCP's newline-delimited stdio framing) and
//! a **pretty** variant for human-readable report files. The parser is a small
//! recursive-descent reader for arbitrary JSON (objects, arrays, strings with
//! `\uXXXX`/surrogate escapes, numbers, booleans, null).

use std::fmt::Write as _;

/// A JSON value. Objects keep insertion order (a `Vec` of pairs) so reports and
/// MCP messages render deterministically.
#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

/// Build an object from `(&str, Json)` pairs (ergonomic constructor).
pub fn obj(pairs: Vec<(&str, Json)>) -> Json {
    Json::Obj(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
}

impl Json {
    /// String value from anything `Into<String>`.
    pub fn str(v: impl Into<String>) -> Json {
        Json::Str(v.into())
    }

    // ---- accessors (ergonomic for MCP dispatch / report diffing) ----

    /// Object field by key, if this is an object containing it.
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_array(&self) -> Option<&[Json]> {
        match self {
            Json::Arr(a) => Some(a),
            _ => None,
        }
    }

    // ---- serialize ----

    /// Compact single-line JSON (used for MCP stdio messages).
    pub fn to_compact(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, None, 0);
        s
    }

    /// Pretty, 2-space-indented JSON (used for human-readable report files).
    pub fn to_pretty(&self) -> String {
        let mut s = String::new();
        self.write(&mut s, Some(2), 0);
        s
    }

    fn write(&self, out: &mut String, indent: Option<usize>, level: usize) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => {
                if !n.is_finite() {
                    out.push_str("null"); // JSON has no NaN/Inf
                } else if *n == n.trunc() && n.abs() < 1e15 {
                    let _ = write!(out, "{}", *n as i64); // integers without ".0"
                } else {
                    let _ = write!(out, "{n}");
                }
            }
            Json::Str(s) => write_escaped(out, s),
            Json::Arr(a) => {
                if a.is_empty() {
                    out.push_str("[]");
                    return;
                }
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, level + 1);
                    v.write(out, indent, level + 1);
                }
                newline_indent(out, indent, level);
                out.push(']');
            }
            Json::Obj(m) => {
                if m.is_empty() {
                    out.push_str("{}");
                    return;
                }
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    newline_indent(out, indent, level + 1);
                    write_escaped(out, k);
                    out.push(':');
                    if indent.is_some() {
                        out.push(' ');
                    }
                    v.write(out, indent, level + 1);
                }
                newline_indent(out, indent, level);
                out.push('}');
            }
        }
    }

    // ---- parse ----

    /// Parse a JSON document, or return an error message on malformed input.
    pub fn parse(input: &str) -> Result<Json, String> {
        let mut p = Parser {
            b: input.as_bytes(),
            i: 0,
            depth: 0,
        };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i != p.b.len() {
            return Err(format!("trailing data at byte {}", p.i));
        }
        Ok(v)
    }
}

fn newline_indent(out: &mut String, indent: Option<usize>, level: usize) {
    if let Some(w) = indent {
        out.push('\n');
        for _ in 0..w * level {
            out.push(' ');
        }
    }
}

fn write_escaped(out: &mut String, s: &str) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

struct Parser<'a> {
    b: &'a [u8],
    i: usize,
    depth: usize,
}

const MAX_DEPTH: usize = 64;

impl<'a> Parser<'a> {
    fn ws(&mut self) {
        while self.i < self.b.len() && matches!(self.b[self.i], b' ' | b'\t' | b'\n' | b'\r') {
            self.i += 1;
        }
    }
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn value(&mut self) -> Result<Json, String> {
        self.ws();
        if self.depth > MAX_DEPTH {
            return Err("JSON nesting too deep".into());
        }
        match self.peek() {
            Some(b'{') => {
                self.depth += 1;
                let r = self.object();
                self.depth -= 1;
                r
            }
            Some(b'[') => {
                self.depth += 1;
                let r = self.array();
                self.depth -= 1;
                r
            }
            Some(b'"') => Ok(Json::Str(self.string()?)),
            Some(b't') => self.literal("true", Json::Bool(true)),
            Some(b'f') => self.literal("false", Json::Bool(false)),
            Some(b'n') => self.literal("null", Json::Null),
            Some(c) if c == b'-' || c.is_ascii_digit() => self.number(),
            Some(c) => Err(format!("unexpected byte '{}' at {}", c as char, self.i)),
            None => Err("unexpected end of input".into()),
        }
    }
    fn literal(&mut self, lit: &str, val: Json) -> Result<Json, String> {
        if self.b[self.i..].starts_with(lit.as_bytes()) {
            self.i += lit.len();
            Ok(val)
        } else {
            Err(format!("invalid literal at {}", self.i))
        }
    }
    fn number(&mut self) -> Result<Json, String> {
        let start = self.i;
        if self.peek() == Some(b'-') {
            self.i += 1;
        }
        while let Some(c) = self.peek() {
            if c.is_ascii_digit() || matches!(c, b'.' | b'e' | b'E' | b'+' | b'-') {
                self.i += 1;
            } else {
                break;
            }
        }
        let s = std::str::from_utf8(&self.b[start..self.i]).map_err(|_| "bad utf8 in number")?;
        s.parse::<f64>()
            .map(Json::Num)
            .map_err(|_| format!("bad number '{s}'"))
    }
    fn string(&mut self) -> Result<String, String> {
        self.i += 1; // opening quote
        let mut s = String::new();
        loop {
            match self.peek() {
                None => return Err("unterminated string".into()),
                Some(b'"') => {
                    self.i += 1;
                    return Ok(s);
                }
                Some(b'\\') => {
                    self.i += 1; // backslash
                    let e = self.peek().ok_or("eof in escape")?;
                    self.i += 1; // selector
                    match e {
                        b'"' => s.push('"'),
                        b'\\' => s.push('\\'),
                        b'/' => s.push('/'),
                        b'n' => s.push('\n'),
                        b't' => s.push('\t'),
                        b'r' => s.push('\r'),
                        b'b' => s.push('\u{0008}'),
                        b'f' => s.push('\u{000C}'),
                        b'u' => s.push(self.unicode_escape()?),
                        _ => return Err(format!("bad escape '\\{}' at {}", e as char, self.i)),
                    }
                }
                Some(_) => {
                    let len = utf8_len(self.b[self.i]);
                    let chunk = self
                        .b
                        .get(self.i..self.i + len)
                        .ok_or("truncated utf8 in string")?;
                    s.push_str(std::str::from_utf8(chunk).map_err(|_| "bad utf8 in string")?);
                    self.i += len;
                }
            }
        }
    }
    /// Reads the 4 hex digits after `\u` (already consumed), resolving surrogate
    /// pairs into a single `char`.
    fn unicode_escape(&mut self) -> Result<char, String> {
        let hi = self.hex4()?;
        if (0xD800..=0xDBFF).contains(&hi) {
            if self.peek() == Some(b'\\') && self.b.get(self.i + 1) == Some(&b'u') {
                self.i += 2; // consume "\u"
                let lo = self.hex4()?;
                if !(0xDC00..=0xDFFF).contains(&lo) {
                    return Err("invalid low surrogate".into());
                }
                let c = 0x10000 + ((hi - 0xD800) << 10) + (lo - 0xDC00);
                return char::from_u32(c).ok_or_else(|| "invalid surrogate pair".into());
            }
            return Err("lone high surrogate".into());
        }
        char::from_u32(hi).ok_or_else(|| "invalid code point".into())
    }
    fn hex4(&mut self) -> Result<u32, String> {
        let mut v = 0u32;
        for _ in 0..4 {
            let c = self.peek().ok_or("short \\u escape")?;
            let d = match c {
                b'0'..=b'9' => (c - b'0') as u32,
                b'a'..=b'f' => (c - b'a' + 10) as u32,
                b'A'..=b'F' => (c - b'A' + 10) as u32,
                _ => return Err("bad hex digit".into()),
            };
            v = v * 16 + d;
            self.i += 1;
        }
        Ok(v)
    }
    fn array(&mut self) -> Result<Json, String> {
        self.i += 1; // [
        let mut a = Vec::new();
        self.ws();
        if self.peek() == Some(b']') {
            self.i += 1;
            return Ok(Json::Arr(a));
        }
        loop {
            a.push(self.value()?);
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b']') => {
                    self.i += 1;
                    return Ok(Json::Arr(a));
                }
                _ => return Err(format!("expected ',' or ']' at {}", self.i)),
            }
        }
    }
    fn object(&mut self) -> Result<Json, String> {
        self.i += 1; // {
        let mut m = Vec::new();
        self.ws();
        if self.peek() == Some(b'}') {
            self.i += 1;
            return Ok(Json::Obj(m));
        }
        loop {
            self.ws();
            if self.peek() != Some(b'"') {
                return Err(format!("expected key string at {}", self.i));
            }
            let k = self.string()?;
            self.ws();
            if self.peek() != Some(b':') {
                return Err(format!("expected ':' at {}", self.i));
            }
            self.i += 1;
            let v = self.value()?;
            m.push((k, v));
            self.ws();
            match self.peek() {
                Some(b',') => self.i += 1,
                Some(b'}') => {
                    self.i += 1;
                    return Ok(Json::Obj(m));
                }
                _ => return Err(format!("expected ',' or '}}' at {}", self.i)),
            }
        }
    }
}

fn utf8_len(b: u8) -> usize {
    if b < 0x80 {
        1
    } else if b >> 5 == 0b110 {
        2
    } else if b >> 4 == 0b1110 {
        3
    } else if b >> 3 == 0b11110 {
        4
    } else {
        1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_compact() {
        let v = obj(vec![
            ("ok", Json::Bool(true)),
            ("n", Json::Num(42.0)),
            ("f", Json::Num(0.5)),
            ("s", Json::str("a\"b\\c\n")),
            ("arr", Json::Arr(vec![Json::Num(1.0), Json::Null])),
            ("empty_obj", Json::Obj(vec![])),
        ]);
        let parsed = Json::parse(&v.to_compact()).expect("parse compact");
        assert_eq!(parsed, v);
        let parsed_pretty = Json::parse(&v.to_pretty()).expect("parse pretty");
        assert_eq!(parsed_pretty, v);
    }

    #[test]
    fn integers_have_no_dot_zero() {
        assert_eq!(Json::Num(128.0).to_compact(), "128");
        assert_eq!(Json::Num(-3.0).to_compact(), "-3");
        assert_eq!(Json::Num(0.25).to_compact(), "0.25");
    }

    #[test]
    fn parses_nested_and_escapes() {
        let j = Json::parse(r#"{ "a": [1, 2.5e1, {"b": "x\tyé"}], "z": false }"#).unwrap();
        assert_eq!(j.get("a").unwrap().as_array().unwrap().len(), 3);
        assert_eq!(
            j.get("a").unwrap().as_array().unwrap()[1].as_f64(),
            Some(25.0)
        );
        let inner = &j.get("a").unwrap().as_array().unwrap()[2];
        assert_eq!(inner.get("b").unwrap().as_str(), Some("x\ty\u{e9}"));
        assert_eq!(j.get("z").unwrap().as_bool(), Some(false));
    }

    #[test]
    fn non_finite_becomes_null() {
        assert_eq!(Json::Num(f64::NAN).to_compact(), "null");
        assert_eq!(Json::Num(f64::INFINITY).to_compact(), "null");
    }

    #[test]
    fn rejects_malformed() {
        assert!(Json::parse("{").is_err());
        assert!(Json::parse("[1,]").is_err());
        assert!(Json::parse("nul").is_err());
        assert!(Json::parse("\"unterminated").is_err());
        assert!(Json::parse("1 2").is_err());
    }

    #[test]
    fn rejects_deep_nesting() {
        let deep = "[".repeat(100) + &"]".repeat(100);
        let r = Json::parse(&deep);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), "JSON nesting too deep");
    }
}
