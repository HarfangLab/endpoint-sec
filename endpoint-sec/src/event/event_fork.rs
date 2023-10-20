//! [`EventFork`]

use endpoint_sec_sys::es_event_fork_t;

use crate::Process;

/// Fork a new process event.
#[doc(alias = "es_event_fork_t")]
pub struct EventFork<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_fork_t,

    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventFork<'a> {
    /// The child process that was created.
    #[inline(always)]
    pub fn child(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.child() }, self.version)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventFork<'_> {}

impl_debug_eq_hash_with_functions!(EventFork<'a> with version; child);
