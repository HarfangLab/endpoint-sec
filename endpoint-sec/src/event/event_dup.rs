//! [`EventDup`]

use endpoint_sec_sys::es_event_dup_t;

use crate::File;

/// Duplicate a file descriptor event.
#[doc(alias = "es_event_dup_t")]
pub struct EventDup<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_dup_t,
}

impl<'a> EventDup<'a> {
    /// Describes the file the duplicated file descriptor points to.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventDup<'_> {}

impl_debug_eq_hash_with_functions!(EventDup<'a>; target);
