//! [`EventUipcConnect`]

use endpoint_sec_sys::es_event_uipc_connect_t;

use crate::File;

/// A UNIX-domain socket is about to be connected.
#[doc(alias = "es_event_uipc_connect_t")]
pub struct EventUipcConnect<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_uipc_connect_t,
}

impl<'a> EventUipcConnect<'a> {
    /// Describes the socket file that the socket is bound to.
    #[inline(always)]
    pub fn file(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.file() })
    }

    /// The communications domain of the socket (see socket(2)).
    #[inline(always)]
    pub fn domain(&self) -> i32 {
        self.raw.domain
    }

    /// Type of the socket (see socket(2)).
    #[inline(always)]
    pub fn type_(&self) -> i32 {
        self.raw.type_
    }

    /// Protocol of the socket (see socket(2)).
    #[inline(always)]
    pub fn protocol(&self) -> i32 {
        self.raw.protocol
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventUipcConnect<'_> {}

impl_debug_eq_hash_with_functions!(EventUipcConnect<'a>; file, domain, type_, protocol);
