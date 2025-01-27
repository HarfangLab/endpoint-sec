//! [`EventPtyGrant`]

use endpoint_sec_sys::{dev_t, es_event_pty_grant_t};

/// A pseudoterminal control device is being granted.
#[doc(alias = "es_event_pty_grant_t")]
pub struct EventPtyGrant<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_pty_grant_t,
}

impl EventPtyGrant<'_> {
    /// Major and minor numbers of device.
    #[inline(always)]
    pub fn dev(&self) -> dev_t {
        self.raw.dev
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventPtyGrant<'_> {}

impl_debug_eq_hash_with_functions!(EventPtyGrant<'a>; dev);
