//! [`EventRemount`]

use endpoint_sec_sys::{es_event_remount_t, statfs};

/// Remount a file system event.
#[doc(alias = "es_event_remount_t")]
pub struct EventRemount<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_remount_t,
}

impl<'a> EventRemount<'a> {
    ///  The file system stats for the file system being mounted.
    #[inline(always)]
    pub fn statfs(&self) -> &'a statfs {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.statfs() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventRemount<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventRemount<'_> {}

impl_debug_eq_hash_with_functions!(EventRemount<'a>; statfs);
