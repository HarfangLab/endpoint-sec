//! [`EventSetregid`]

use endpoint_sec_sys::{es_event_setregid_t, uid_t};

/// A process has called `setregid()`.
#[doc(alias = "es_event_setregid_t")]
pub struct EventSetregid<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setregid_t,
}

impl EventSetregid<'_> {
    /// `egid` argument to the `setregid()` call.
    #[inline(always)]
    pub fn egid(&self) -> uid_t {
        self.raw.egid
    }

    /// `ruid` argument to the `setregid()` call.
    #[inline(always)]
    pub fn ruid(&self) -> uid_t {
        self.raw.rgid
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetregid<'_> {}

impl_debug_eq_hash_with_functions!(EventSetregid<'a>; egid, ruid);
