//! [`EventSetuid`]

use endpoint_sec_sys::{es_event_setuid_t, uid_t};

/// A process has called `setuid()`.
#[doc(alias = "es_event_setuid_t")]
pub struct EventSetuid<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setuid_t,
}

impl EventSetuid<'_> {
    /// Argument to the `setuid()` call.
    #[inline(always)]
    pub fn uid(&self) -> uid_t {
        self.raw.uid
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetuid<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSetuid<'_> {}

impl_debug_eq_hash_with_functions!(EventSetuid<'a>; uid);
