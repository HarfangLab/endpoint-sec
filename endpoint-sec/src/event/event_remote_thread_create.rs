//! [`EventRemoteThreadCreate`]

use endpoint_sec_sys::es_event_remote_thread_create_t;

use crate::{Process, ThreadState};

/// A process has attempted to create a thread in another process
#[doc(alias = "es_event_remote_thread_create_t")]
pub struct EventRemoteThreadCreate<'a> {
    /// Raw reference
    pub(crate) raw: &'a es_event_remote_thread_create_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventRemoteThreadCreate<'a> {
    /// Process for which the task name port will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.target() }, self.version)
    }

    /// New thread state, present in case of `thread_create_running`, absent in case of `thread_create`.
    #[inline(always)]
    pub fn thread_state(&self) -> Option<ThreadState<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.thread_state() }.map(ThreadState::new)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventRemoteThreadCreate<'_> {}

impl_debug_eq_hash_with_functions!(EventRemoteThreadCreate<'a> with version; target, thread_state);
