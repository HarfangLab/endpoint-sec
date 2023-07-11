//! [`EventLookup`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_lookup_t;

use crate::File;

/// Lookup a file system object event.
#[doc(alias = "es_event_lookup_t")]
pub struct EventLookup<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_lookup_t,
}

impl<'a> EventLookup<'a> {
    /// The current directory.
    #[inline(always)]
    pub fn source_dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source_dir() })
    }

    /// The path to lookup relative to the current directory.
    #[inline(always)]
    pub fn relative_target(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.relative_target.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventLookup<'_> {}

impl_debug_eq_hash_with_functions!(EventLookup<'a>; source_dir, relative_target);
