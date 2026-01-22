//! [`EventRemount`]

use endpoint_sec_sys::{es_event_remount_t, statfs};
#[cfg(feature = "macos_15_0_0")]
use endpoint_sec_sys::es_mount_disposition_t;

/// Remount a file system event.
#[doc(alias = "es_event_remount_t")]
#[cfg_attr(not(feature = "macos_15_0_0"), allow(dead_code))]
pub struct EventRemount<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_remount_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventRemount<'a> {
    /// The file system stats for the file system being mounted.
    #[inline(always)]
    pub fn statfs(&self) -> &'a statfs {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.statfs() }
    }

    /// The provided remount flags.
    ///
    /// Field available only if message version >= 8.
    #[inline(always)]
    #[cfg(feature = "macos_15_0_0")]
    pub fn remount_flags(&self) -> Option<u64> {
        if self.version >= 8 {
            Some(self.raw.remount_flags)
        } else {
            None
        }
    }

    /// The device disposition of the f_mntfromname.
    ///
    /// Field available only if message version >= 8.
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
unsafe impl Send for EventRemount<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventRemount<'_> {}

impl_debug_eq_hash_with_functions!(EventRemount<'a>;
    statfs,
    #[cfg(feature = "macos_15_0_0")] remount_flags,
    #[cfg(feature = "macos_15_0_0")] disposition
);
