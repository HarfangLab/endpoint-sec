//! [`EventExit`]

use endpoint_sec_sys::es_event_exit_t;

/// Terminate a process event.
#[doc(alias = "es_event_exit_t")]
pub struct EventExit<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_exit_t,
}

impl EventExit<'_> {
    /// The exit status of a process.
    #[inline(always)]
    pub fn stat(&self) -> i32 {
        self.raw.stat
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventExit<'_> {}

impl_debug_eq_hash_with_functions!(EventExit<'a>; stat);
