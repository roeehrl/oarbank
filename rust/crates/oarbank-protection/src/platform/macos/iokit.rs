//! The few IOKit calls the macOS backend needs (the GPU meter's registry walk, the HID idle time), with an
//! owning wrapper that releases on drop.

use std::ffi::{c_char, CStr};
use std::ptr;

use super::cf::{self, CFTypeRef, Owned};

pub type IoObject = u32;
type KernReturn = i32;
type MatchingDict = *mut std::ffi::c_void;

#[link(name = "IOKit", kind = "framework")]
extern "C" {
    pub fn IORegistryCreateIterator(
        main_port: u32,
        plane: *const c_char,
        options: u32,
        it: *mut IoObject,
    ) -> KernReturn;
    pub fn IOIteratorNext(it: IoObject) -> IoObject;
    pub fn IOObjectConformsTo(o: IoObject, class: *const c_char) -> u32;
    fn IOObjectRelease(o: IoObject) -> KernReturn;
    fn IORegistryEntryCreateCFProperty(
        entry: IoObject,
        key: CFTypeRef,
        alloc: CFTypeRef,
        options: u32,
    ) -> CFTypeRef;
    fn IOServiceMatching(name: *const c_char) -> MatchingDict;
    fn IOServiceGetMatchingService(main_port: u32, matching: MatchingDict) -> IoObject;
}

/// An owned IOKit object reference.
pub struct Object(pub IoObject);

impl Drop for Object {
    fn drop(&mut self) {
        // SAFETY: we own this IOKit reference.
        unsafe { IOObjectRelease(self.0) };
    }
}

/// A registry entry's property (+1), or None.
pub fn property(entry: IoObject, key: &str) -> Option<Owned> {
    let k = cf::string(key)?;
    // SAFETY: entry is a live registry entry; the result is a +1 CF object or NULL.
    Owned::from_create(unsafe { IORegistryEntryCreateCFProperty(entry, k.get(), ptr::null(), 0) })
}

/// The first registered service of a class.
pub fn matching_service(class: &CStr) -> Option<Object> {
    // SAFETY: IOServiceMatching returns a dictionary that IOServiceGetMatchingService consumes; 0 is the
    // default main port.
    let svc = unsafe { IOServiceGetMatchingService(0, IOServiceMatching(class.as_ptr())) };
    (svc != 0).then_some(Object(svc))
}
