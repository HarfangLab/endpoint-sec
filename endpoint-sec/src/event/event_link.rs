//! [`EventLink`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_link_t;

use crate::File;

/// Link to a file event.
#[doc(alias = "es_event_link_t")]
pub struct EventLink<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_link_t,
}

impl<'a> EventLink<'a> {
    /// The existing object to which a hard link will be created.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// The directory in which the link will be created.
    #[inline(always)]
    pub fn target_dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target_dir() })
    }

    /// The name of the new object linked to the source file.
    #[inline(always)]
    pub fn target_filename(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.target_filename.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventLink<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventLink<'_> {}

impl_debug_eq_hash_with_functions!(EventLink<'a>; source, target_dir, target_filename);
