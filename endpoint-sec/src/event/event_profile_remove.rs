//! [`EventProfileRemove`]

use endpoint_sec_sys::es_event_profile_remove_t;

use crate::{AuditToken, Process, Profile};

/// Notification for Profiles removed on the system.
#[doc(alias = "es_event_profile_remove_t")]
pub struct EventProfileRemove<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_profile_remove_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventProfileRemove<'a> {
    /// Process that instigated the Profile removal.
    #[inline(always)]
    pub fn instigator(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.instigator()? };
        Some(Process::new(process, self.version))
    }

    /// Audit token of the process that instigated this event.
    pub fn instigator_token(&self) -> AuditToken {
        #[cfg(feature = "macos_15_0_0")]
        if self.version >= 8 {
            return AuditToken(self.raw.instigator_token);
        }

        // On old versions, the process was always non-null, and we can get
        // its token easily.
        self.instigator().unwrap().audit_token()
    }

    /// Profile install item.
    #[inline(always)]
    pub fn profile(&self) -> Profile<'a> {
        Profile {
            // Safety: 'a tied to self, object obtained through ES
            raw: unsafe { self.raw.profile.as_ref() },
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventProfileRemove<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventProfileRemove<'_> {}

impl_debug_eq_hash_with_functions!(EventProfileRemove<'a> with version; instigator, instigator_token, profile);
