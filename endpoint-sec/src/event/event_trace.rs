//! [`EventTrace`]

use endpoint_sec_sys::es_event_trace_t;

use crate::Process;

/// Fired when one process attempts to attach to another process event.
#[doc(alias = "es_event_trace_t")]
pub struct EventTrace<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_trace_t,

    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventTrace<'a> {
    /// The process that will be attached to by the process that instigated the event.
    #[inline(always)]
    pub fn target(&self) -> Process<'_> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.target() }, self.version)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventTrace<'_> {}

impl_debug_eq_hash_with_functions!(EventTrace<'a> with version; target);
