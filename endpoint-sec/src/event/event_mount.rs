//! [`EventMount`]

use endpoint_sec_sys::{es_event_mount_t, statfs};

/// Mount a file system event.
#[doc(alias = "es_event_mount_t")]
pub struct EventMount<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_mount_t,
}

impl<'a> EventMount<'a> {
    ///  The file system stats for the file system being mounted.
    #[inline(always)]
    pub fn statfs(&self) -> &'a statfs {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.statfs() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventMount<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventMount<'_> {}

impl_debug_eq_hash_with_functions!(EventMount<'a>; statfs);
