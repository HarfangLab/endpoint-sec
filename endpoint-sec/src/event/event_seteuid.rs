//! [`EventSeteuid`]

use endpoint_sec_sys::{es_event_seteuid_t, uid_t};

/// A process has called `seteuid()`.
#[doc(alias = "es_event_seteuid_t")]
pub struct EventSeteuid<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_seteuid_t,
}

impl<'a> EventSeteuid<'a> {
    /// Argument to the `seteuid()` call.
    #[inline(always)]
    pub fn euid(&self) -> uid_t {
        self.raw.euid
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSeteuid<'_> {}

impl_debug_eq_hash_with_functions!(EventSeteuid<'a>; euid);
