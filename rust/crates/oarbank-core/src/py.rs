//! Small re-implementations of the Python builtins the reference SDK leans on (`str.isspace`, `str.strip`,
//! `str.splitlines`, `int(s, base)`, `repr(s)`), so accept/refuse decisions and messages match it.
//!
//! Decimal digits are ASCII only: Python's `int()` also accepts other Unicode decimal digits (`int("٤٤٣")`), which no
//! Oarbank document legitimately contains.

/// `str.isspace` for one character: Unicode White_Space plus the ASCII information separators U+001C..U+001F.
pub fn isspace(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// `str.strip()` with no argument.
pub fn strip(s: &str) -> &str {
    s.trim_matches(isspace)
}

/// `str.splitlines()`: splits on every Python line boundary, drops the separators and the empty tail.
pub fn splitlines(s: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut start = 0;
    let mut it = s.char_indices().peekable();
    while let Some((i, c)) = it.next() {
        let is_break = matches!(
            c,
            '\n' | '\r' | '\u{0b}' | '\u{0c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}'
        );
        if !is_break {
            continue;
        }
        out.push(&s[start..i]);
        let mut end = i + c.len_utf8();
        if c == '\r' {
            if let Some(&(j, '\n')) = it.peek() {
                it.next();
                end = j + 1;
            }
        }
        start = end;
    }
    if start < s.len() {
        out.push(&s[start..]);
    }
    out
}

/// `int(s, base)` for base 8 or 10: surrounding whitespace, an optional sign, an optional `0o` prefix (base 8),
/// single underscores between digits. Values beyond i128 saturate (they never equal anything they are compared to).
pub fn int(s: &str, base: u32) -> Option<i128> {
    let t = strip(s);
    let (neg, t) = match t.as_bytes().first() {
        Some(b'-') => (true, &t[1..]),
        Some(b'+') => (false, &t[1..]),
        _ => (false, t),
    };
    let mut t = t;
    let mut after_prefix = false;
    if base == 8 && (t.starts_with("0o") || t.starts_with("0O")) {
        t = &t[2..];
        after_prefix = true;
    }
    if after_prefix {
        if let Some(r) = t.strip_prefix('_') {
            t = r; // `0o_644` is valid in Python
        }
    }
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return None;
    }
    let mut v: i128 = 0;
    let mut saturated = false;
    for c in t.chars() {
        if c == '_' {
            continue;
        }
        let d = c.to_digit(base)? as i128; // ASCII digits only
        if !saturated {
            match v.checked_mul(base as i128).and_then(|x| x.checked_add(d)) {
                Some(x) => v = x,
                None => saturated = true,
            }
        }
    }
    if saturated {
        v = i128::MAX;
    }
    Some(if neg { -v } else { v })
}

/// `repr(s)` for a str: exact for ASCII; other characters are kept unless they are control or separator characters.
pub fn repr(s: &str) -> String {
    let q = if s.contains('\'') && !s.contains('"') { '"' } else { '\'' };
    let mut out = String::with_capacity(s.len() + 2);
    out.push(q);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == q => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => out.push_str(&format!("\\x{:02x}", c as u32)),
            c if !c.is_ascii() && (c.is_control() || (c.is_whitespace() && c != ' ')) => {
                let n = c as u32;
                if n <= 0xff {
                    out.push_str(&format!("\\x{n:02x}"));
                } else if n <= 0xffff {
                    out.push_str(&format!("\\u{n:04x}"));
                } else {
                    out.push_str(&format!("\\U{n:08x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push(q);
    out
}

/// `oct(v)`: `0o644`, `-0o5`, `0o0`.
pub fn oct(v: i128) -> String {
    if v < 0 {
        format!("-0o{:o}", v.unsigned_abs())
    } else {
        format!("0o{v:o}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_matches_python() {
        assert_eq!(int("443", 10), Some(443));
        assert_eq!(int(" 4_43 ", 10), Some(443));
        assert_eq!(int("+0443", 10), Some(443));
        assert_eq!(int("-1", 10), Some(-1));
        for bad in ["", " ", "4__43", "_443", "443_", "0x1bb", "4 43", "abc", "+", "١"] {
            assert_eq!(int(bad, 10), None, "{bad:?}");
        }
        assert_eq!(int("0o644", 8), Some(0o644));
        assert_eq!(int("0O_755", 8), Some(0o755));
        assert_eq!(int("100755", 8), Some(0o100755));
        assert_eq!(int(" 6_44 ", 8), Some(0o644));
        for bad in ["0o", "8", "0o_", "_644", "0x1"] {
            assert_eq!(int(bad, 8), None, "{bad:?}");
        }
        assert_eq!(int(&"9".repeat(60), 10), Some(i128::MAX));
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines(""), Vec::<&str>::new());
        assert_eq!(splitlines("\n"), vec![""]);
        assert_eq!(splitlines("a\nb"), vec!["a", "b"]);
        assert_eq!(splitlines("a\r\nb\r"), vec!["a", "b"]);
        assert_eq!(splitlines("a\u{2028}b\u{0c}c\u{1c}d"), vec!["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n\nb\n"), vec!["a", "", "b"]);
    }

    #[test]
    fn repr_matches_python() {
        assert_eq!(repr("a"), "'a'");
        assert_eq!(repr("it's"), "\"it's\"");
        assert_eq!(repr("'\""), "'\\'\"'");
        assert_eq!(repr("a\\b\n\x01\x7f"), "'a\\\\b\\n\\x01\\x7f'");
        assert_eq!(repr("naïve"), "'naïve'");
        assert_eq!(oct(0o644), "0o644");
        assert_eq!(oct(-5), "-0o5");
    }

    #[test]
    fn isspace_includes_separators() {
        assert!(isspace('\u{1f}') && isspace('\u{85}') && isspace('\u{3000}') && !isspace('\u{200b}'));
        assert_eq!(strip("\u{1c} x \t"), "x");
    }
}
