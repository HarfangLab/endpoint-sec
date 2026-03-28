//! [`EventAuthorizationPetition`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_authorization_petition_t, es_string_token_t};

use crate::{AuditToken, Process};

/// Notification that a process petitioned for certain authorization rights
#[doc(alias = "es_event_authorization_petition_t")]
pub struct EventAuthorizationPetition<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_authorization_petition_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventAuthorizationPetition<'a> {
    /// Process that submitted the petition (XPC caller)
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

    /// Process that created the petition
    #[inline(always)]
    pub fn petitioner(&self) -> Option<Process<'a>> {
        Some(Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.petitioner.as_ref()? },
            self.version,
        ))
    }

    /// Audit token of the process that created the petition.
    pub fn petitioner_token(&self) -> AuditToken {
        #[cfg(feature = "macos_15_0_0")]
        if self.version >= 8 {
            return AuditToken(self.raw.petitioner_token);
        }

        // On old versions, the process was always non-null, and we can get
        // its token easily.
        self.petitioner().unwrap().audit_token()
    }

    /// Flags associated with the petition. Defined in Security framework "Authorization/Authorization.h"
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.raw.flags
    }

    /// Number of rights being requested.
    #[inline(always)]
    pub fn right_count(&self) -> usize {
        self.raw.right_count
    }

    /// Iterator over the rights
    #[inline(always)]
    pub fn rights<'event>(&'event self) -> AuthorizationPetitionRights<'event, 'a> {
        AuthorizationPetitionRights::new(self)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthorizationPetition<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventAuthorizationPetition<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthorizationPetition<'a> with version; instigator, instigator_token, petitioner, petitioner_token, flags, right_count);

/// Read the `idx` right of `raw`
///
/// # Safety
///
/// Must be called with a valid event for which `idx` is in range `0..raw.right_count`
unsafe fn read_nth_right(raw: &es_event_authorization_petition_t, idx: usize) -> es_string_token_t {
    std::ptr::read(raw.rights.add(idx))
}

make_event_data_iterator!(
    EventAuthorizationPetition;
    /// Iterator over the rights of an [`EventAuthorizationPetition`]
    AuthorizationPetitionRights with right_count (usize);
    &'raw OsStr;
    read_nth_right,
    super::as_os_str,
);
