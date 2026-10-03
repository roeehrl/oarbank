//! The few X11 protocol messages the Linux front-app lookup needs (the core protocol and EWMH): the connection
//! setup with an Xauthority cookie, InternAtom, and GetProperty for the root's `_NET_ACTIVE_WINDOW` and that
//! window's `_NET_WM_PID`. Encoding and decoding are platform-neutral so that every OS tests them; the Linux
//! backend does the socket I/O.

/// Xauthority's FamilyLocal (an address that is the host name) and FamilyWild.
const FAMILY_LOCAL: u16 = 256;
const FAMILY_WILD: u16 = 65535;
pub const MIT_MAGIC_COOKIE: &str = "MIT-MAGIC-COOKIE-1";

/// One Xauthority entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthEntry {
    pub family: u16,
    pub address: Vec<u8>,
    pub display: String,
    pub name: String,
    pub data: Vec<u8>,
}

/// Parse an Xauthority file: entries of a big-endian family, then four length-prefixed fields.
pub fn parse_xauthority(b: &[u8]) -> Vec<AuthEntry> {
    fn field<'a>(b: &'a [u8], i: &mut usize) -> Option<&'a [u8]> {
        let n = u16::from_be_bytes([*b.get(*i)?, *b.get(*i + 1)?]) as usize;
        let v = b.get(*i + 2..*i + 2 + n)?;
        *i += 2 + n;
        Some(v)
    }
    let mut out = vec![];
    let mut i = 0;
    while i + 2 <= b.len() {
        let family = u16::from_be_bytes([b[i], b[i + 1]]);
        i += 2;
        let (Some(address), Some(display), Some(name), Some(data)) = (
            field(b, &mut i),
            field(b, &mut i),
            field(b, &mut i),
            field(b, &mut i),
        ) else {
            break;
        };
        out.push(AuthEntry {
            family,
            address: address.to_vec(),
            display: String::from_utf8_lossy(display).into_owned(),
            name: String::from_utf8_lossy(name).into_owned(),
            data: data.to_vec(),
        });
    }
    out
}

/// The cookie for a local display, as libxcb chooses it: a MIT-MAGIC-COOKIE-1 entry for this host (or any host)
/// and this display number (or any).
pub fn cookie<'a>(entries: &'a [AuthEntry], hostname: &str, display: u32) -> Option<&'a [u8]> {
    entries
        .iter()
        .find(|e| {
            e.name == MIT_MAGIC_COOKIE
                && (e.family == FAMILY_WILD
                    || (e.family == FAMILY_LOCAL && e.address == hostname.as_bytes()))
                && (e.display.is_empty() || e.display == display.to_string())
        })
        .map(|e| e.data.as_slice())
}

/// The display number of a local display name (":0", ":1.0", "unix:0"); None for a remote one.
pub fn display_number(display: &str) -> Option<u32> {
    let (host, rest) = display.rsplit_once(':')?;
    if !(host.is_empty() || host == "unix") {
        return None;
    }
    rest.split('.').next()?.parse().ok()
}

fn pad4(n: usize) -> usize {
    (4 - n % 4) % 4
}

fn push_padded(out: &mut Vec<u8>, b: &[u8]) {
    out.extend_from_slice(b);
    out.extend(std::iter::repeat_n(0, pad4(b.len())));
}

/// The connection setup request (little-endian, protocol 11.0).
pub fn setup_request(auth_name: &str, auth_data: &[u8]) -> Vec<u8> {
    let mut out = vec![b'l', 0];
    out.extend_from_slice(&11u16.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&(auth_name.len() as u16).to_le_bytes());
    out.extend_from_slice(&(auth_data.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    push_padded(&mut out, auth_name.as_bytes());
    push_padded(&mut out, auth_data);
    out
}

/// The setup reply's 8-byte header: Ok(bytes of additional data) when the server accepted us, Err(reason)
/// otherwise (the reason follows in the additional data).
pub fn setup_header(h: &[u8; 8]) -> Result<usize, usize> {
    let more = u16::from_le_bytes([h[6], h[7]]) as usize * 4;
    if h[0] == 1 {
        Ok(more)
    } else {
        Err(more)
    }
}

/// The first screen's root window from the setup reply's additional data.
pub fn root_window(data: &[u8]) -> Option<u32> {
    let u16_at = |i: usize| Some(u16::from_le_bytes([*data.get(i)?, *data.get(i + 1)?]) as usize);
    let vendor = u16_at(16)?;
    let screens = *data.get(20)?;
    let formats = *data.get(21)? as usize;
    if screens == 0 {
        return None;
    }
    let screen = 32 + vendor + pad4(vendor) + 8 * formats;
    Some(u32::from_le_bytes(
        data.get(screen..screen + 4)?.try_into().ok()?,
    ))
}

/// InternAtom (opcode 16), only if the atom exists.
pub fn intern_atom(name: &str) -> Vec<u8> {
    let len = (8 + name.len() + pad4(name.len())) / 4;
    let mut out = vec![16, 1];
    out.extend_from_slice(&(len as u16).to_le_bytes());
    out.extend_from_slice(&(name.len() as u16).to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    push_padded(&mut out, name.as_bytes());
    out
}

/// GetProperty (opcode 20) for one 32-bit value of any type.
pub fn get_property(window: u32, property: u32) -> Vec<u8> {
    let mut out = vec![20, 0];
    out.extend_from_slice(&6u16.to_le_bytes());
    for v in [window, property, 0, 0, 1] {
        out.extend_from_slice(&v.to_le_bytes());
    }
    out
}

/// A 32-byte reply's extra length (bytes after the first 32), or None for an error or event.
pub fn reply_extra(r: &[u8; 32]) -> Option<usize> {
    (r[0] == 1).then(|| u32::from_le_bytes([r[4], r[5], r[6], r[7]]) as usize * 4)
}

/// An InternAtom reply's atom (0: no such atom).
pub fn atom_of(r: &[u8; 32]) -> u32 {
    u32::from_le_bytes([r[8], r[9], r[10], r[11]])
}

/// A GetProperty reply's first 32-bit value (None: no such property, or not 32-bit).
pub fn property_u32(r: &[u8; 32], value: &[u8]) -> Option<u32> {
    let format = r[1];
    let items = u32::from_le_bytes([r[16], r[17], r[18], r[19]]);
    if format != 32 || items == 0 {
        return None;
    }
    Some(u32::from_le_bytes(value.get(..4)?.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(family: u16, address: &[u8], display: &str, name: &str, data: &[u8]) -> Vec<u8> {
        let mut out = family.to_be_bytes().to_vec();
        for f in [address, display.as_bytes(), name.as_bytes(), data] {
            out.extend_from_slice(&(f.len() as u16).to_be_bytes());
            out.extend_from_slice(f);
        }
        out
    }

    #[test]
    fn picks_the_cookie_for_this_host_and_display() {
        let mut file = entry(FAMILY_LOCAL, b"otherhost", "0", MIT_MAGIC_COOKIE, &[1; 16]);
        file.extend(entry(FAMILY_LOCAL, b"box", "1", MIT_MAGIC_COOKIE, &[2; 16]));
        file.extend(entry(
            FAMILY_LOCAL,
            b"box",
            "0",
            "XDM-AUTHORIZATION-1",
            &[3; 16],
        ));
        file.extend(entry(FAMILY_LOCAL, b"box", "0", MIT_MAGIC_COOKIE, &[4; 16]));
        let e = parse_xauthority(&file);
        assert_eq!(e.len(), 4);
        assert_eq!(cookie(&e, "box", 0), Some(&[4u8; 16][..]));
        assert_eq!(cookie(&e, "box", 1), Some(&[2u8; 16][..]));
        assert_eq!(cookie(&e, "box", 7), None);
        // GDM's Xauthority holds one wildcard entry
        let gdm = parse_xauthority(&entry(FAMILY_WILD, b"", "", MIT_MAGIC_COOKIE, &[9; 16]));
        assert_eq!(cookie(&gdm, "anything", 3), Some(&[9u8; 16][..]));
        // a truncated file yields the complete entries only
        assert_eq!(parse_xauthority(&file[..file.len() - 3]).len(), 3);
    }

    #[test]
    fn local_display_numbers() {
        assert_eq!(display_number(":0"), Some(0));
        assert_eq!(display_number(":1.0"), Some(1));
        assert_eq!(display_number("unix:2"), Some(2));
        assert_eq!(display_number("remote:0"), None);
        assert_eq!(display_number(""), None);
    }

    #[test]
    fn encodes_requests() {
        let s = setup_request(MIT_MAGIC_COOKIE, &[0xab; 16]);
        assert_eq!(&s[..12], &[b'l', 0, 11, 0, 0, 0, 18, 0, 16, 0, 0, 0]);
        assert_eq!(s.len(), 12 + 20 + 16); // the 18-byte name padded to 20
        assert_eq!(setup_request("", &[]).len(), 12);
        let a = intern_atom("_NET_ACTIVE_WINDOW");
        assert_eq!(&a[..8], &[16, 1, 7, 0, 18, 0, 0, 0]);
        assert_eq!(a.len(), 28);
        let g = get_property(0x1e6, 0x150);
        assert_eq!(
            g,
            [20, 0, 6, 0, 0xe6, 1, 0, 0, 0x50, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]
        );
    }

    #[test]
    fn decodes_replies() {
        // a setup reply as Xvfb sends it: vendor "The X.Org Foundation" (20 bytes), 7 pixmap formats, root 0x3d0
        let mut data = vec![0u8; 32];
        data[16..18].copy_from_slice(&20u16.to_le_bytes());
        data[20] = 1;
        data[21] = 7;
        data.extend_from_slice(b"The X.Org Foundation");
        data.extend_from_slice(&[0; 56]);
        data.extend_from_slice(&0x3d0u32.to_le_bytes());
        data.extend_from_slice(&[0; 36]);
        assert_eq!(root_window(&data), Some(0x3d0));
        let mut h = [1, 0, 11, 0, 0, 0, 0, 0];
        h[6..8].copy_from_slice(&((data.len() / 4) as u16).to_le_bytes());
        assert_eq!(setup_header(&h), Ok(data.len()));
        assert_eq!(setup_header(&[0, 21, 11, 0, 0, 0, 7, 0]), Err(28)); // refused: "Authorization required…"
        let mut atom = [0u8; 32];
        atom[0] = 1;
        atom[8..12].copy_from_slice(&0x150u32.to_le_bytes());
        assert_eq!((reply_extra(&atom), atom_of(&atom)), (Some(0), 0x150));
        let mut error = [0u8; 32];
        error[1] = 3; // BadWindow
        assert_eq!(reply_extra(&error), None);
        // GetProperty: format 32, type WINDOW, one item
        let mut prop = [0u8; 32];
        prop[0] = 1;
        prop[1] = 32;
        prop[4] = 1;
        prop[16] = 1;
        assert_eq!(reply_extra(&prop), Some(4));
        assert_eq!(
            property_u32(&prop, &0x1400007u32.to_le_bytes()),
            Some(0x1400007)
        );
        let missing = [
            1u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0,
        ];
        assert_eq!(property_u32(&missing, &[]), None);
    }
}
