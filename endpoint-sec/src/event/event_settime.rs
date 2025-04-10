//! [`EventSetTime`]

use endpoint_sec_sys::es_event_settime_t;

/// Modify the system time event.
#[doc(alias = "es_event_settime_t")]
pub struct EventSetTime<'a> {
    /// Raw event
    #[allow(dead_code)]
    pub(crate) raw: &'a es_event_settime_t,
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetTime<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSetTime<'_> {}

impl_debug_eq_hash_with_functions!(EventSetTime<'a>;);
