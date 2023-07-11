//! [`EventReadLink`]

use endpoint_sec_sys::es_event_readlink_t;

use crate::File;

/// Resolve a symbolic link event.
#[doc(alias = "es_event_readlink_t")]
pub struct EventReadLink<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_readlink_t,
}

impl<'a> EventReadLink<'a> {
    /// The symbolic link that is attempting to be resolved.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventReadLink<'_> {}

impl_debug_eq_hash_with_functions!(EventReadLink<'a>; source);
