//! [`EventSignal`]

use endpoint_sec_sys::es_event_signal_t;

use crate::Process;

/// Send a signal to a process event.
///
/// Signals may be sent on behalf of another process or directly. Notably
/// launchd often sends signals on behalf of another process for service start/
/// stop operations. If this is the case an instigator will be provided. The
/// relationship between each process is illustrated below:
///
/// Delegated Signal:
///
/// ```
/// Instigator Process -> IPC to Sender Process (launchd) -> Target Process
/// ```
///
/// Direct Signal:
///
/// ```
/// Sender Process -> Target Process
/// ```
///
/// Clients may wish to block delegated signals from launchd for non-authorized
/// instigators, while still allowing direct signals initiated by launchd for
/// shutdown/reboot/restart.
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

    /// Process information for the instigator.
    ///
    /// Only available for delegated signals.
    ///
    /// Note: Only available only if message version >= 9.
    #[cfg(feature = "macos_15_4_0")]
    #[inline(always)]
    pub fn instigator(&self) -> Option<Process<'a>> {
        if self.version >= 9 {
            // Safety: 'a tied to self, object obtained through ES
            let process = unsafe { self.raw.instigator()? };
            Some(Process::new(process, self.version))
        } else {
            None
        }
    }

}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSignal<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSignal<'_> {}

impl_debug_eq_hash_with_functions!(EventSignal<'a> with version; sig, target, #[cfg(feature = "macos_15_4_0")] instigator);
