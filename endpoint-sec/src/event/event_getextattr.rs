//! [`EventGetExtAttr`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_getextattr_t;

use crate::File;

/// Retrieve an extended attribute event.
#[doc(alias = "es_event_getextattr_t")]
pub struct EventGetExtAttr<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_getextattr_t,
}

impl<'a> EventGetExtAttr<'a> {
    /// The extended attribute which will be retrieved.
    #[inline(always)]
    pub fn extattr(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.extattr.as_os_str() }
    }

    /// The file for which the extended attribute will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventGetExtAttr<'_> {}

impl_debug_eq_hash_with_functions!(EventGetExtAttr<'a>; extattr, target);
