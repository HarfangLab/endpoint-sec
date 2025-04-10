//! [`EventGetTaskInspect`]

use endpoint_sec_sys::{es_event_get_task_inspect_t, es_get_task_type_t};

use crate::Process;

/// Get a process's task inspect port.
///
/// This event is fired when a process obtains a send right to a task inspect
/// port (e.g. `task_inspect_for_pid()`, `task_identity_token_get_task_port()`).
#[doc(alias = "es_event_get_task_inspect_t")]
pub struct EventGetTaskInspect<'a> {
    /// Raw reference
    pub(crate) raw: &'a es_event_get_task_inspect_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventGetTaskInspect<'a> {
    /// Process for which the task inspect port will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.target() }, self.version)
    }

    /// Indicates how the process is obtaining the task for the target process.
    ///
    /// Note: only available if message version >= 5.
    #[inline(always)]
    pub fn type_(&self) -> Option<es_get_task_type_t> {
        if self.version < 5 {
            None
        } else {
            Some(self.raw.type_)
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventGetTaskInspect<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventGetTaskInspect<'_> {}

impl_debug_eq_hash_with_functions!(EventGetTaskInspect<'a> with version; target, type_);
