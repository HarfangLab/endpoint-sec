//! [`EventChroot`]

use endpoint_sec_sys::es_event_chroot_t;

use crate::File;

/// Change the root directory for a process event.
#[doc(alias = "es_event_chroot_t")]
pub struct EventChroot<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_chroot_t,
}

impl<'a> EventChroot<'a> {
    /// The directory which will be the new root.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventChroot<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventChroot<'_> {}

impl_debug_eq_hash_with_functions!(EventChroot<'a>; target);
