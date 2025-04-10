//! [`EventXpcConnect`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_xpc_connect_t, es_xpc_domain_type_t};

/// Notification for an XPC connection being established to a named service.
#[doc(alias = "es_event_xpc_connect_t")]
pub struct EventXpcConnect<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_xpc_connect_t,
}

impl<'a> EventXpcConnect<'a> {
    /// Service name of the named service.
    #[inline(always)]
    pub fn service_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.service_name.as_os_str() }
    }

    /// The type of XPC domain in which the service resides in.
    #[inline(always)]
    pub fn service_domain_type(&self) -> es_xpc_domain_type_t {
        self.raw.service_domain_type
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventXpcConnect<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventXpcConnect<'_> {}

impl_debug_eq_hash_with_functions!(EventXpcConnect<'a>; service_name, service_domain_type);
