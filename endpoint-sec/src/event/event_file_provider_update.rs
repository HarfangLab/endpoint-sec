//! [`EventFileProviderUpdate`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_file_provider_update_t;

use crate::File;

/// Update file contents via the FileProvider framework event.
#[doc(alias = "es_event_file_provider_update_t")]
pub struct EventFileProviderUpdate<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_file_provider_update_t,
}

impl<'a> EventFileProviderUpdate<'a> {
    /// The staged file that has had its contents updated.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// The destination that the staged `source` file will be moved to.
    #[inline(always)]
    pub fn target_path(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.target_path.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventFileProviderUpdate<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventFileProviderUpdate<'_> {}

impl_debug_eq_hash_with_functions!(EventFileProviderUpdate<'a>; source, target_path);
