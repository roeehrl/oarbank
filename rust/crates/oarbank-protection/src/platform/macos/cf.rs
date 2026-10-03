//! The few CoreFoundation calls the macOS backend needs, with an owning wrapper that releases on drop.

#![allow(non_upper_case_globals)]

use std::ffi::{c_char, c_void};
use std::ptr;

pub type CFTypeRef = *const c_void;
pub type CFIndex = isize;
pub type CFTypeID = usize;
pub type Boolean = u8;

const UTF8: u32 = 0x0800_0100;
const NUMBER_SINT32: CFIndex = 3;
const NUMBER_FLOAT64: CFIndex = 6;

#[repr(C)]
pub struct CallBacks {
    _opaque: [usize; 6],
}

#[link(name = "CoreFoundation", kind = "framework")]
extern "C" {
    static kCFTypeDictionaryKeyCallBacks: CallBacks;
    static kCFTypeDictionaryValueCallBacks: CallBacks;
    fn CFRelease(cf: CFTypeRef);
    fn CFGetTypeID(cf: CFTypeRef) -> CFTypeID;
    fn CFStringGetTypeID() -> CFTypeID;
    fn CFNumberGetTypeID() -> CFTypeID;
    fn CFArrayGetTypeID() -> CFTypeID;
    fn CFDictionaryGetTypeID() -> CFTypeID;
    fn CFStringCreateWithBytes(
        alloc: CFTypeRef,
        bytes: *const u8,
        len: CFIndex,
        encoding: u32,
        external: Boolean,
    ) -> CFTypeRef;
    fn CFStringGetLength(s: CFTypeRef) -> CFIndex;
    fn CFStringGetMaximumSizeForEncoding(len: CFIndex, encoding: u32) -> CFIndex;
    fn CFStringGetCString(s: CFTypeRef, buf: *mut c_char, size: CFIndex, encoding: u32) -> Boolean;
    fn CFNumberCreate(alloc: CFTypeRef, kind: CFIndex, value: *const c_void) -> CFTypeRef;
    fn CFNumberGetValue(n: CFTypeRef, kind: CFIndex, value: *mut c_void) -> Boolean;
    fn CFDictionaryCreate(
        alloc: CFTypeRef,
        keys: *const CFTypeRef,
        values: *const CFTypeRef,
        n: CFIndex,
        key_callbacks: *const CallBacks,
        value_callbacks: *const CallBacks,
    ) -> CFTypeRef;
    fn CFDictionaryGetValue(d: CFTypeRef, key: CFTypeRef) -> CFTypeRef;
    fn CFArrayGetCount(a: CFTypeRef) -> CFIndex;
    fn CFArrayGetValueAtIndex(a: CFTypeRef, i: CFIndex) -> CFTypeRef;
    fn CFDataCreate(alloc: CFTypeRef, bytes: *const u8, len: CFIndex) -> CFTypeRef;
    fn CFPropertyListCreateWithData(
        alloc: CFTypeRef,
        data: CFTypeRef,
        options: usize,
        format: *mut CFIndex,
        error: *mut CFTypeRef,
    ) -> CFTypeRef;
}

/// An owned (+1) CoreFoundation reference.
pub struct Owned(CFTypeRef);

impl Owned {
    /// Take ownership of a +1 reference (None for NULL).
    pub fn from_create(r: CFTypeRef) -> Option<Self> {
        (!r.is_null()).then_some(Self(r))
    }

    pub fn get(&self) -> CFTypeRef {
        self.0
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        // SAFETY: we hold the only +1 reference.
        unsafe { CFRelease(self.0) }
    }
}

pub fn string(s: &str) -> Option<Owned> {
    // SAFETY: the bytes outlive the call; CoreFoundation copies them.
    Owned::from_create(unsafe {
        CFStringCreateWithBytes(ptr::null(), s.as_ptr(), s.len() as CFIndex, UTF8, 0)
    })
}

pub fn number_i32(v: i32) -> Option<Owned> {
    // SAFETY: CFNumberCreate copies the value.
    Owned::from_create(unsafe {
        CFNumberCreate(ptr::null(), NUMBER_SINT32, (&v as *const i32).cast())
    })
}

/// A dictionary of CF keys and values (both retained by the dictionary).
pub fn dictionary(pairs: &[(CFTypeRef, CFTypeRef)]) -> Option<Owned> {
    let keys: Vec<CFTypeRef> = pairs.iter().map(|p| p.0).collect();
    let values: Vec<CFTypeRef> = pairs.iter().map(|p| p.1).collect();
    // SAFETY: the arrays hold valid CF objects for the call; the callbacks retain them.
    Owned::from_create(unsafe {
        CFDictionaryCreate(
            ptr::null(),
            keys.as_ptr(),
            values.as_ptr(),
            pairs.len() as CFIndex,
            &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks,
        )
    })
}

fn is(r: CFTypeRef, type_id: unsafe extern "C" fn() -> CFTypeID) -> bool {
    // SAFETY: r is a valid CF object or NULL (checked).
    !r.is_null() && unsafe { CFGetTypeID(r) == type_id() }
}

/// A borrowed CFString's contents.
pub fn to_string(r: CFTypeRef) -> Option<String> {
    if !is(r, CFStringGetTypeID) {
        return None;
    }
    // SAFETY: r is a CFString; the buffer is sized for the longest UTF-8 encoding plus NUL.
    unsafe {
        let len = CFStringGetMaximumSizeForEncoding(CFStringGetLength(r), UTF8) + 1;
        let mut buf = vec![0u8; len.max(1) as usize];
        if CFStringGetCString(r, buf.as_mut_ptr().cast(), len, UTF8) == 0 {
            return None;
        }
        let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
        Some(String::from_utf8_lossy(&buf[..end]).into_owned())
    }
}

/// A borrowed CFNumber as a double.
pub fn to_f64(r: CFTypeRef) -> Option<f64> {
    if !is(r, CFNumberGetTypeID) {
        return None;
    }
    let mut v = 0f64;
    // SAFETY: r is a CFNumber; v is a valid f64 out-pointer.
    (unsafe { CFNumberGetValue(r, NUMBER_FLOAT64, (&mut v as *mut f64).cast()) } != 0).then_some(v)
}

/// A borrowed value from a borrowed CFDictionary (None when `d` is not a dictionary or the key is missing).
pub fn dict_get(d: CFTypeRef, key: CFTypeRef) -> CFTypeRef {
    if !is(d, CFDictionaryGetTypeID) {
        return ptr::null();
    }
    // SAFETY: d is a CFDictionary and key a CF object.
    unsafe { CFDictionaryGetValue(d, key) }
}

pub fn dict_get_str(d: CFTypeRef, key: &str) -> CFTypeRef {
    match string(key) {
        Some(k) => dict_get(d, k.get()),
        None => ptr::null(),
    }
}

/// The borrowed elements of a borrowed CFArray (empty when `a` is not an array).
pub fn array_items(a: CFTypeRef) -> Vec<CFTypeRef> {
    if !is(a, CFArrayGetTypeID) {
        return vec![];
    }
    // SAFETY: a is a CFArray; indices are within its count.
    unsafe {
        (0..CFArrayGetCount(a))
            .map(|i| CFArrayGetValueAtIndex(a, i))
            .collect()
    }
}

/// Parse an XML or binary property list.
pub fn property_list(bytes: &[u8]) -> Option<Owned> {
    // SAFETY: CFDataCreate copies the bytes; the property list call only reads the data.
    unsafe {
        let data = Owned::from_create(CFDataCreate(
            ptr::null(),
            bytes.as_ptr(),
            bytes.len() as CFIndex,
        ))?;
        Owned::from_create(CFPropertyListCreateWithData(
            ptr::null(),
            data.get(),
            0,
            ptr::null_mut(),
            ptr::null_mut(),
        ))
    }
}
