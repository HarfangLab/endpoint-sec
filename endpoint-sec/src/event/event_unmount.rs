//! [`EventUnmount`]

use endpoint_sec_sys::{es_event_unmount_t, statfs};

/// Unmount a file system event.
#[doc(alias = "es_event_unmount_t")]
pub struct EventUnmount<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_unmount_t,
}

impl<'a> EventUnmount<'a> {
    ///  The file system stats for the file system being unmounted.
    #[inline(always)]
    pub fn statfs(&self) -> &'a statfs {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.statfs() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventUnmount<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventUnmount<'_> {}

impl_debug_eq_hash_with_functions!(EventUnmount<'a>; statfs);
