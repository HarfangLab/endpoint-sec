//! [`EventWrite`]

use endpoint_sec_sys::es_event_write_t;

use crate::File;

/// Write to a file event.
#[doc(alias = "es_event_write_t")]
pub struct EventWrite<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_write_t,
}

impl<'a> EventWrite<'a> {
    /// The file being written to.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventWrite<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventWrite<'_> {}

impl_debug_eq_hash_with_functions!(EventWrite<'a>; target);
