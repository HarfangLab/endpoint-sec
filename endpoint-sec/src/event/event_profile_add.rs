//! [`EventProfileAdd`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_profile_add_t, es_profile_source_t, es_profile_t};

use crate::Process;

/// Notification for Profiles installed on the system.
#[doc(alias = "es_event_profile_add_t")]
pub struct EventProfileAdd<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_profile_add_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventProfileAdd<'a> {
    /// Process that instigated the Profile install or update.
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator.as_ref() }, self.version)
    }

    /// `true` if the event is an update to an already installed profile.
    #[inline(always)]
    pub fn is_update(&self) -> bool {
        self.raw.is_update
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
unsafe impl Send for EventProfileAdd<'_> {}

impl_debug_eq_hash_with_functions!(EventProfileAdd<'a> with version; instigator, is_update, profile);

/// Structure describing a Profile event
#[doc(alias = "es_profile_t")]
pub struct Profile<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_profile_t,
}

impl<'a> Profile<'a> {
    /// Profile identifier.
    #[inline(always)]
    pub fn identifier(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.identifier.as_os_str() }
    }

    /// Profile UUID.
    #[inline(always)]
    pub fn uuid(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.uuid.as_os_str() }
    }

    /// Source of Profile installation (MDM/Manual Install)
    #[inline(always)]
    pub fn install_source(&self) -> es_profile_source_t {
        self.raw.install_source
    }

    /// Profile organization name.
    #[inline(always)]
    pub fn organization(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.organization.as_os_str() }
    }

    /// Profile display name.
    #[inline(always)]
    pub fn display_name(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.display_name.as_os_str() }
    }

    /// Profile scope.
    #[inline(always)]
    pub fn scope(&self) -> &'a OsStr {
        // Safety: lifetime matches that of message
        unsafe { self.raw.scope.as_os_str() }
    }
}

impl_debug_eq_hash_with_functions!(Profile<'a>; identifier, uuid, install_source, organization, display_name, scope);
