//! [`EventClone`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_clone_t;

use crate::File;

/// Clone a file event.
#[doc(alias = "es_event_clone_t")]
pub struct EventClone<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_clone_t,
}

impl<'a> EventClone<'a> {
    /// The file that will be cloned.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// The directory into which the `source` file will be cloned.
    #[inline(always)]
    pub fn target_dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target_dir() })
    }

    /// The name of the new file to which `source` will be cloned.
    #[inline(always)]
    pub fn target_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.target_name.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventClone<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventClone<'_> {}

impl_debug_eq_hash_with_functions!(EventClone<'a>; source, target_dir, target_name);
