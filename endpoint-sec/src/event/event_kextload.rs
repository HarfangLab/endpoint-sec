//! [`EventKextLoad`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_kextload_t;

/// Load a kernel extension event.
#[doc(alias = "es_event_kextload_t")]
pub struct EventKextLoad<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_kextload_t,
}

impl<'a> EventKextLoad<'a> {
    /// The signing identifier of the kext being loaded.
    #[inline(always)]
    pub fn identifier(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.identifier.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventKextLoad<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventKextLoad<'_> {}

impl_debug_eq_hash_with_functions!(EventKextLoad<'a>; identifier);
