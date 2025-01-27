//! [`EventSetegid`]

use endpoint_sec_sys::{es_event_setegid_t, uid_t};

/// A process has called `setegid()`.
#[doc(alias = "es_event_setegid_t")]
pub struct EventSetegid<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setegid_t,
}

impl EventSetegid<'_> {
    /// Argument to the `setegid()` call.
    #[inline(always)]
    pub fn egid(&self) -> uid_t {
        self.raw.egid
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetegid<'_> {}

impl_debug_eq_hash_with_functions!(EventSetegid<'a>; egid);
