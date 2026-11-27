// SPDX-License-Identifier: AGPL-3.0-or-later

//! Windows: whether a file belongs to the current user. The only `unsafe`
//! code of the crate: Windows has no safe API for a file's owner.

#![allow(unsafe_code)]

use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;

use windows_sys::Win32::Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    EqualSid, GetTokenInformation, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    TOKEN_INFORMATION_CLASS, TOKEN_OWNER, TOKEN_QUERY, TOKEN_USER, TokenOwner, TokenUser,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

/// Whether `path` is owned by the current user, or by this process's
/// default owner for new objects (elevated administrators' files may
/// belong to the Administrators group).
pub(crate) fn is_ours(path: &Path) -> io::Result<bool> {
    let wide: Vec<u16> = path.as_os_str().encode_wide().chain([0]).collect();
    let mut owner: PSID = ptr::null_mut();
    let mut descriptor: PSECURITY_DESCRIPTOR = ptr::null_mut();
    // SAFETY: `wide` is NUL-terminated; on success `descriptor` is freed
    // below with LocalFree, and `owner` points into it.
    let status = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION,
            &raw mut owner,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &raw mut descriptor,
        )
    };
    if status != ERROR_SUCCESS {
        return Err(io::Error::from_raw_os_error(status.cast_signed()));
    }
    let result = token_sids().map(|sids| {
        sids.iter().any(|sid| {
            // SAFETY: both SIDs are valid: `owner` while `descriptor` lives,
            // `sid` while `sids` does.
            unsafe { EqualSid(owner, sid.as_ptr().cast_mut().cast()) != 0 }
        })
    });
    // SAFETY: `descriptor` was allocated by GetNamedSecurityInfoW.
    unsafe { LocalFree(descriptor.cast()) };
    result
}

/// The current user's SID and the token's default owner SID, as the raw
/// TOKEN_USER / TOKEN_OWNER buffers (each starts with a pointer to its SID).
fn token_sids() -> io::Result<Vec<SidBuf>> {
    let mut token: HANDLE = ptr::null_mut();
    // SAFETY: the pseudo-handle of the current process needs no closing.
    if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw mut token) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let sids = [TokenUser, TokenOwner]
        .into_iter()
        .map(|class| SidBuf::query(token, class))
        .collect();
    // SAFETY: `token` was opened above.
    unsafe { CloseHandle(token) };
    sids
}

/// A TOKEN_USER or TOKEN_OWNER: a buffer whose first field points to a SID
/// stored later in the same buffer.
struct SidBuf {
    buf: Vec<u64>,
}

impl SidBuf {
    fn query(token: HANDLE, class: TOKEN_INFORMATION_CLASS) -> io::Result<Self> {
        let mut len = 0u32;
        // SAFETY: a size query: no buffer is written.
        unsafe { GetTokenInformation(token, class, ptr::null_mut(), 0, &raw mut len) };
        // u64 elements: aligned for the pointer the structure starts with.
        let mut buf = vec![0u64; (len as usize).div_ceil(8)];
        // SAFETY: `buf` holds at least `len` bytes.
        let ok = unsafe {
            GetTokenInformation(token, class, buf.as_mut_ptr().cast(), len, &raw mut len)
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self { buf })
    }

    fn as_ptr(&self) -> *const core::ffi::c_void {
        // Both structures start with the SID pointer: TOKEN_USER's
        // `User.Sid`, TOKEN_OWNER's `Owner`.
        const _: () = assert!(std::mem::offset_of!(TOKEN_OWNER, Owner) == 0);
        const _: () = assert!(std::mem::offset_of!(TOKEN_USER, User) == 0);
        const _: () = assert!(
            std::mem::offset_of!(windows_sys::Win32::Security::SID_AND_ATTRIBUTES, Sid) == 0
        );
        // SAFETY: the buffer was filled with one of those structures.
        unsafe { *self.buf.as_ptr().cast::<PSID>() }.cast_const()
    }
}
