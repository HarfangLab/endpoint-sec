//! Types and definitions used in Endpoint Security but not declared in the ES headers
//!
//! The types here are not available in the [`libc`] crate either and only one of them is available
//! in the [`mach2`](https://docs.rs/mach2) crate.

use core::fmt;
use std::os::raw::c_int;
pub use std::os::raw::{c_uint, c_ushort};

use libc::{dev_t, gid_t, pid_t, uid_t};
pub use mach2::vm_types::user_addr_t;

pub type user_size_t = u64;

pub type attrgroup_t = u32;

pub type au_asid_t = pid_t;

/// Pointer to opaque type for Endpoint Security ACL.
///
/// The ACL provided cannot be directly used by functions within the `<sys/acl.h>` header. These
/// functions can mutate the struct passed into them, which is not compatible with the immutable
/// nature of `es_message_t`. Additionally, because this field is minimally constructed, you
/// must not use `acl_dup(3)` to get a mutable copy, as this can lead to out of bounds memory
/// access. To obtain a `acl_t` struct that is able to be used with all functions within `<sys/
/// acl.h>`, please use a combination of `acl_copy_ext(3)` followed by `acl_copy_int(3)`.
#[cfg(feature = "macos_10_15_1")]
pub type acl_t = *mut _acl;

/// Never use directly, use [`acl_t`] instead
#[repr(C)]
#[cfg(feature = "macos_10_15_1")]
pub struct _acl {
    _unused: [u8; 0],
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct au_tid_t {
    pub port: dev_t,
    pub machine: u32,
}

/// The audit token is an opaque token which identifies Mach tasks and senders of Mach messages
/// as subjects to the BSM audit system.  Only the appropriate BSM library routines should
/// be used to interpret the contents of the audit token as the representation of the subject
/// identity within the token may change over time.
///
/// Starting with macOS 11, almost all audit functions have been deprecated (see the system
/// header `bsm/libbsm.h`), do not use them if your program target more recent versions of
/// macOS.
#[repr(C)]
#[derive(Default, Copy, Clone, PartialEq, Eq, Hash)]
pub struct audit_token_t {
    /// Value of the token
    ///
    /// This is considered an opaque value, do not rely on its format
    pub val: [c_uint; 8],
}

// Make the debug representation an hex string to make it shorter and clearer when debugging
impl fmt::Debug for audit_token_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("audit_token_t")
            .field(&format!("0x{:08X}", self))
            .finish()
    }
}

impl fmt::LowerHex for audit_token_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self.val {
            fmt::LowerHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

impl fmt::UpperHex for audit_token_t {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for v in self.val {
            fmt::UpperHex::fmt(&v, f)?;
        }

        Ok(())
    }
}

#[repr(C)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct attrlist {
    /// number of attr. bit sets in list (should be 5)
    pub bitmapcount: c_ushort,
    /// (to maintain 4-byte alignment)
    _reserved: u16,
    /// common attribute group
    pub commonattr: attrgroup_t,
    /// Volume attribute group
    pub volattr: attrgroup_t,
    /// directory attribute group
    pub dirattr: attrgroup_t,
    /// file attribute group
    pub fileattr: attrgroup_t,
    /// fork attribute group
    pub forkattr: attrgroup_t,
}

#[link(name = "bsm", kind = "dylib")]
extern "C" {
    /// Extract information from an [`audit_token_t`], used to identify Mach tasks and senders
    /// of Mach messages as subjects to the audit system. `audit_tokent_to_au32()` is the only
    /// method that should be used to parse an `audit_token_t`, since its internal representation
    /// may change over time. A pointer parameter may be `NULL` if that information is not needed.
    /// `audit_token_to_au32()` has been deprecated because the terminal ID information is no
    /// longer saved in this token. The last parameter is actually the process ID version. The
    /// API calls [`audit_token_to_auid()`], [`audit_token_to_euid()`], [`audit_token_to_ruid()`],
    /// [`audit_token_to_rgid()`], [`audit_token_to_pid()`], [`audit_token_to_asid()`], and/or
    /// [`audit_token_to_pidversion()`] should be used instead.
    ///
    /// Note: **this function has been deprecated by Apple in an unknown version**.
    ///
    /// - `atoken`: the audit token containing the desired information
    /// - `auidp`: Pointer to a `uid_t`; on return will be set to the task or sender's audit user ID
    /// - `euidp`: Pointer to a `uid_t`; on return will be set to the task or sender's effective
    ///   user ID
    /// - `egidp`: Pointer to a `gid_t`; on return will be set to the task or sender's effective
    ///   group ID
    /// - `ruidp`: Pointer to a `uid_t`; on return will be set to the task or sender's real user ID
    /// - `rgidp`: Pointer to a `gid_t`; on return will be set to the task or sender's real group ID
    /// - `pidp`: Pointer to a `pid_t`; on return will be set to the task or sender's process ID
    /// - `asidp`: Pointer to an `au_asid_t`; on return will be set to the task or sender's audit
    ///   session ID
    /// - `tidp`: Pointer to an `au_tid_t`; on return will be set to the process ID version and NOT
    ///   THE SENDER'S TERMINAL ID.
    ///
    /// IMPORTANT: In Apple's `bsm-8`, these are marked `__APPLE_API_PRIVATE`.
    pub fn audit_token_to_au32(
        atoken: audit_token_t,
        auidp: *mut uid_t,
        euidp: *mut uid_t,
        egidp: *mut gid_t,
        ruidp: *mut uid_t,
        rgidp: *mut gid_t,
        pidp: *mut pid_t,
        asidp: *mut au_asid_t,
        tidp: *mut au_tid_t,
    );

    /// Extract the audit user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The audit user ID extracted from the Mach audit token.
    pub fn audit_token_to_auid(atoken: audit_token_t) -> uid_t;

    /// Extract the effective user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The effective user ID extracted from the Mach audit token.
    pub fn audit_token_to_euid(atoken: audit_token_t) -> uid_t;

    /// Extract the effective group ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The effective group ID extracted from the Mach audit token.
    pub fn audit_token_to_egid(atoken: audit_token_t) -> gid_t;

    /// Extract the real user ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The real user ID extracted from the Mach audit token.
    pub fn audit_token_to_ruid(atoken: audit_token_t) -> uid_t;

    /// Extract the real group ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The real group ID extracted from the Mach audit token.
    pub fn audit_token_to_rgid(atoken: audit_token_t) -> gid_t;

    /// Extract the process ID from an `audit_token_t`, used to identify Mach tasks and senders
    /// of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The process ID extracted from the Mach audit token.
    pub fn audit_token_to_pid(atoken: audit_token_t) -> pid_t;

    /// Extract the audit session ID from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The audit session ID extracted from the Mach audit token.
    pub fn audit_token_to_asid(atoken: audit_token_t) -> au_asid_t;

    /// Extract the process ID version from an `audit_token_t`, used to identify Mach tasks and
    /// senders of Mach messages as subjects of the audit system.
    ///
    /// - `atoken`: The Mach audit token.
    /// - Returns: The process ID version extracted from the Mach audit token.
    pub fn audit_token_to_pidversion(atoken: audit_token_t) -> c_int;
}
