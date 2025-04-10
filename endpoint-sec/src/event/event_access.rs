//! [`EventAccess`]

use endpoint_sec_sys::es_event_access_t;

use crate::File;

/// View stat information of a file event.
#[doc(alias = "es_event_access_t")]
pub struct EventAccess<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_access_t,
}

impl<'a> EventAccess<'a> {
    /// Access permission to check.
    #[inline(always)]
    pub fn mode(&self) -> i32 {
        self.raw.mode
    }

    /// The file to check for access.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAccess<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventAccess<'_> {}

impl_debug_eq_hash_with_functions!(
    EventAccess<'a>;
    mode,
    target,
);
