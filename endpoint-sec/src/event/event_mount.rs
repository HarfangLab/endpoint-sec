//! [`EventMount`]

use endpoint_sec_sys::{es_event_mount_t, statfs};
#[cfg(feature = "macos_15_0_0")]
use endpoint_sec_sys::es_mount_disposition_t;

/// Mount a file system event.
#[doc(alias = "es_event_mount_t")]
#[cfg_attr(not(feature = "macos_15_0_0"), allow(dead_code))]
pub struct EventMount<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_mount_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventMount<'a> {
    /// The file system stats for the file system being mounted.
    #[inline(always)]
    pub fn statfs(&self) -> &'a statfs {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.statfs() }
    }

    /// The disposition of the device being mounted.
    ///
    /// Note: only available if message version >= 8.
    #[inline(always)]
    #[cfg(feature = "macos_15_0_0")]
    pub fn disposition(&self) -> Option<es_mount_disposition_t> {
        if self.version >= 8 {
            Some(self.raw.disposition)
        } else {
            None
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventMount<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventMount<'_> {}

impl_debug_eq_hash_with_functions!(EventMount<'a>; statfs, #[cfg(feature = "macos_15_0_0")] disposition);
