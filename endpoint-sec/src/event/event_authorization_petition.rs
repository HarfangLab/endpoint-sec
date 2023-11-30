//! [`EventAuthorizationPetition`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_authorization_petition_t, es_string_token_t};

use crate::Process;

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
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator.as_ref() }, self.version)
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

impl_debug_eq_hash_with_functions!(EventAuthorizationPetition<'a> with version; instigator, petitioner, flags, right_count);

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
