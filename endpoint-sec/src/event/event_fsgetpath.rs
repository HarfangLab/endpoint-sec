//! [`EventFsGetPath`]

use endpoint_sec_sys::es_event_fsgetpath_t;

use crate::File;

/// Retrieve file system path based on FSID event.
#[doc(alias = "es_event_fsgetpath_t")]
pub struct EventFsGetPath<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_fsgetpath_t,
}

impl<'a> EventFsGetPath<'a> {
    /// Describes the file system path that will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventFsGetPath<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventFsGetPath<'_> {}

impl_debug_eq_hash_with_functions!(EventFsGetPath<'a>; target);
