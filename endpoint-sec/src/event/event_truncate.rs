//! [`EventTruncate`]

use endpoint_sec_sys::es_event_truncate_t;

use crate::File;

/// Truncate a file event.
#[doc(alias = "es_event_truncate_t")]
pub struct EventTruncate<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_truncate_t,
}

impl<'a> EventTruncate<'a> {
    /// The file that is being truncated.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventTruncate<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventTruncate<'_> {}

impl_debug_eq_hash_with_functions!(EventTruncate<'a>; target);
