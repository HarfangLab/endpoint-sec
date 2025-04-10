//! [`EventProcSuspendResume`]

use endpoint_sec_sys::{es_event_proc_suspend_resume_t, es_proc_suspend_resume_type_t};

use crate::Process;

/// One of `pid_suspend()`, `pid_resume()` or `pid_shutdown_sockets()` is being called on a process.
#[doc(alias = "es_event_proc_suspend_resume_t")]
pub struct EventProcSuspendResume<'a> {
    /// Raw reference
    pub(crate) raw: &'a es_event_proc_suspend_resume_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventProcSuspendResume<'a> {
    /// Process that is being suspended, resumed or is the object of a `pid_shutdown_sockets()` call.
    #[inline(always)]
    pub fn target(&self) -> Option<Process<'a>> {
        Some(Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.target() }?,
            self.version,
        ))
    }

    /// Type of operation called on the target process.
    #[inline(always)]
    pub fn type_(&self) -> es_proc_suspend_resume_type_t {
        self.raw.type_
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventProcSuspendResume<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventProcSuspendResume<'_> {}

impl_debug_eq_hash_with_functions!(EventProcSuspendResume<'a> with version; target, type_);
