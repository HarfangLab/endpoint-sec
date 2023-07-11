//! [`EventGetTask`]

use endpoint_sec_sys::{es_event_get_task_t, es_get_task_type_t};

use crate::Process;

/// Get a process's task control port event.
#[doc(alias = "es_event_get_task_t")]
pub struct EventGetTask<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_get_task_t,

    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventGetTask<'a> {
    /// Type indicating how the process is obtaining the task port for the target process on version 5 or later, otherwise None.
    #[inline(always)]
    pub fn task_type(&self) -> Option<es_get_task_type_t> {
        if self.version >= 5 {
            Some(self.raw.type_)
        } else {
            None
        }
    }

    /// The process for which the task control port will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> Process<'_> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.target() }, self.version)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventGetTask<'_> {}

impl_debug_eq_hash_with_functions!(EventGetTask<'a> with version; task_type, target);
