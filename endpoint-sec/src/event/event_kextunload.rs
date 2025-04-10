//! [`EventKextUnload`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_kextunload_t;

/// Unload a kernel extension event.
#[doc(alias = "es_event_kextunload_t")]
pub struct EventKextUnload<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_kextunload_t,
}

impl<'a> EventKextUnload<'a> {
    /// The signing identifier of the kext being unloaded.
    #[inline(always)]
    pub fn identifier(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.identifier.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventKextUnload<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventKextUnload<'_> {}

impl_debug_eq_hash_with_functions!(EventKextUnload<'a>; identifier);
