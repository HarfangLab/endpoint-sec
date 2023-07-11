//! [`EventSetreuid`]

use endpoint_sec_sys::{es_event_setreuid_t, uid_t};

/// A process has called `setreuid()`.
#[doc(alias = "es_event_setreuid_t")]
pub struct EventSetreuid<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setreuid_t,
}

impl<'a> EventSetreuid<'a> {
    /// `euid` argument to the `setreuid()` call.
    #[inline(always)]
    pub fn euid(&self) -> uid_t {
        self.raw.euid
    }

    /// `ruid` argument to the `setreuid()` call.
    #[inline(always)]
    pub fn ruid(&self) -> uid_t {
        self.raw.ruid
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetreuid<'_> {}

impl_debug_eq_hash_with_functions!(EventSetreuid<'a>; euid, ruid);
