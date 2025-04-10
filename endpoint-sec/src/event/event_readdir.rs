//! [`EventReadDir`]

use endpoint_sec_sys::es_event_readdir_t;

use crate::File;

/// Read directory entries event.
#[doc(alias = "es_event_readdir_t")]
pub struct EventReadDir<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_readdir_t,
}

impl<'a> EventReadDir<'a> {
    /// The directory whose contents will be read.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventReadDir<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventReadDir<'_> {}

impl_debug_eq_hash_with_functions!(EventReadDir<'a>; target);
