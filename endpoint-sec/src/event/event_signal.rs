//! [`EventSignal`]

use endpoint_sec_sys::es_event_signal_t;

use crate::Process;

/// Send a signal to a process event.
#[doc(alias = "es_event_signal_t")]
pub struct EventSignal<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_signal_t,

    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventSignal<'a> {
    /// The signal number to be delivered.
    #[inline(always)]
    pub fn sig(&self) -> i32 {
        self.raw.sig
    }

    /// The process that will receive the signal.
    #[inline(always)]
    pub fn target(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.target() }, self.version)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSignal<'_> {}

impl_debug_eq_hash_with_functions!(EventSignal<'a> with version; sig, target);
