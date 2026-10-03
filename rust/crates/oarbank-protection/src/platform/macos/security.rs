//! Code-signing identity of a running process through the Security framework: no root and no entitlement
//! needed for same-user processes (SecCodeCopyGuestWithAttributes with a pid).

#![allow(non_upper_case_globals)]

use std::ffi::c_void;
use std::ptr;

use super::cf::{self, CFTypeRef, Owned};
use crate::table::SigningIdentity;

type OSStatus = i32;
const ERR_SEC_SUCCESS: OSStatus = 0;
/// kSecCSSigningInformation
const SIGNING_INFORMATION: u32 = 1 << 1;

#[link(name = "Security", kind = "framework")]
extern "C" {
    static kSecGuestAttributePid: CFTypeRef;
    static kSecCodeInfoTeamIdentifier: CFTypeRef;
    static kSecCodeInfoIdentifier: CFTypeRef;
    fn SecCodeCopyGuestWithAttributes(
        host: *const c_void,
        attributes: CFTypeRef,
        flags: u32,
        guest: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCopyStaticCode(code: CFTypeRef, flags: u32, static_code: *mut CFTypeRef) -> OSStatus;
    fn SecCodeCopySigningInformation(
        code: CFTypeRef,
        flags: u32,
        information: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecRequirementCreateWithString(
        text: CFTypeRef,
        flags: u32,
        requirement: *mut CFTypeRef,
    ) -> OSStatus;
    fn SecCodeCheckValidity(code: CFTypeRef, flags: u32, requirement: CFTypeRef) -> OSStatus;
}

/// The running code of `pid` (a SecCode).
fn sec_code(pid: i32) -> Option<Owned> {
    let n = cf::number_i32(pid)?;
    // SAFETY: kSecGuestAttributePid is a constant CFString exported by Security.
    let attrs = cf::dictionary(&[(unsafe { kSecGuestAttributePid }, n.get())])?;
    let mut code: CFTypeRef = ptr::null();
    // SAFETY: attrs is a valid dictionary; code receives a +1 reference on success.
    let rc = unsafe { SecCodeCopyGuestWithAttributes(ptr::null(), attrs.get(), 0, &mut code) };
    if rc != ERR_SEC_SUCCESS {
        return None;
    }
    Owned::from_create(code)
}

/// Team ID and signing identifier (None for unsigned or ad-hoc code, or a process that is gone).
pub fn signing(pid: i32) -> SigningIdentity {
    let none = SigningIdentity::default();
    let Some(code) = sec_code(pid) else {
        return none;
    };
    let mut sc: CFTypeRef = ptr::null();
    // SAFETY: code is a valid SecCode; sc receives a +1 SecStaticCode on success.
    if unsafe { SecCodeCopyStaticCode(code.get(), 0, &mut sc) } != ERR_SEC_SUCCESS {
        return none;
    }
    let Some(sc) = Owned::from_create(sc) else {
        return none;
    };
    let mut info: CFTypeRef = ptr::null();
    // SAFETY: sc is a valid SecStaticCode; info receives a +1 CFDictionary on success.
    if unsafe { SecCodeCopySigningInformation(sc.get(), SIGNING_INFORMATION, &mut info) }
        != ERR_SEC_SUCCESS
    {
        return none;
    }
    let Some(info) = Owned::from_create(info) else {
        return none;
    };
    // SAFETY: the keys are constant CFStrings exported by Security; values are borrowed from info.
    let (team, ident) = unsafe {
        (
            cf::to_string(cf::dict_get(info.get(), kSecCodeInfoTeamIdentifier)),
            cf::to_string(cf::dict_get(info.get(), kSecCodeInfoIdentifier)),
        )
    };
    SigningIdentity {
        team_id: team,
        signing_id: ident,
    }
}

/// Does the live process satisfy a code-signing requirement string (SecCodeCheckValidity)?
pub fn satisfies(pid: i32, requirement: &str) -> bool {
    let Some(code) = sec_code(pid) else {
        return false;
    };
    let Some(text) = cf::string(requirement) else {
        return false;
    };
    let mut req: CFTypeRef = ptr::null();
    // SAFETY: text is a valid CFString; req receives a +1 SecRequirement on success.
    if unsafe { SecRequirementCreateWithString(text.get(), 0, &mut req) } != ERR_SEC_SUCCESS {
        return false;
    }
    let Some(req) = Owned::from_create(req) else {
        return false;
    };
    // SAFETY: code and req are valid Security objects.
    unsafe { SecCodeCheckValidity(code.get(), 0, req.get()) == ERR_SEC_SUCCESS }
}
