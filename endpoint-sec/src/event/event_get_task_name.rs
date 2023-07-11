//! [`EventGetTaskName`]

use endpoint_sec_sys::{es_event_get_task_name_t, es_get_task_type_t};

use crate::Process;

/// Get a process's task name port
#[doc(alias = "es_event_get_task_name_t")]
pub struct EventGetTaskName<'a> {
    /// Raw reference
    pub(crate) raw: &'a es_event_get_task_name_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventGetTaskName<'a> {
    /// Process for which the task name port will be retrieved.
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
unsafe impl Send for EventGetTaskName<'_> {}

impl_debug_eq_hash_with_functions!(EventGetTaskName<'a> with version; target, type_);
