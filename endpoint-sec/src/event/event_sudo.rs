//! [`EventSudo`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_sudo_t, es_sudo_plugin_type_t, es_sudo_reject_info_t};
use libc::uid_t;

/// A sudo event.
#[doc(alias = "es_event_sudo_t")]
pub struct EventSudo<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_sudo_t,
}

impl<'a> EventSudo<'a> {
    /// True iff sudo was successful
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// Optional. When success is false, describes why sudo was rejected
    #[inline(always)]
    pub fn reject_info(&self) -> Option<RejectInfo<'a>> {
        match self.success() && (self.raw.reject_info.is_null() == false) {
            false => None,
            true => Some(RejectInfo {
                // Safety: 'a tied to self, object obtained through ES
                raw: unsafe { &*self.raw.reject_info },
            }),
        }
    }
    /// Describes whether or not the from_uid is interpretable
    #[inline(always)]
    pub fn has_from_uid(&self) -> bool {
        self.raw.has_from_uid
    }
    /// Optional. The uid of the user who initiated the su
    #[inline(always)]
    pub fn from_uid(&self) -> Option<uid_t> {
        // Safety: 'a tied to self, object obtained through ES
        #[allow(clippy::unnecessary_lazy_evaluations)]
        self.has_from_uid().then(|| unsafe { self.raw.from_uid.uid })
    }
    /// Optional. The name of the user who initiated the su
    #[inline(always)]
    pub fn from_username(&self) -> Option<&'a OsStr> {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.from_username.as_opt_os_str() }
    }
    /// Describes whether or not the to_uid is interpretable
    #[inline(always)]
    pub fn has_to_uid(&self) -> bool {
        self.raw.has_to_uid
    }
    /// Optional. If success, the user ID that is going to be substituted
    #[inline(always)]
    pub fn to_uid(&self) -> Option<uid_t> {
        if self.success() == false {
            return None;
        }
        // Safety: 'a tied to self, object obtained through ES
        #[allow(clippy::unnecessary_lazy_evaluations)]
        self.has_to_uid().then(|| unsafe { self.raw.to_uid.uid })
    }
    /// Optional. If success, the user name that is going to be substituted
    #[inline(always)]
    pub fn to_username(&self) -> Option<&'a OsStr> {
        if self.success() == false {
            return None;
        }
        // Safety: 'a tied to self, object obtained through ES
        unsafe { Some(self.raw.to_username.as_os_str()) }
    }
    /// Optional. The command to be run
    #[inline(always)]
    pub fn command(&self) -> Option<&'a OsStr> {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.command.as_opt_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSudo<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSudo<'_> {}

impl_debug_eq_hash_with_functions!(EventSudo<'a>; success, reject_info, has_from_uid, from_uid, from_username, has_to_uid, to_uid, to_username, command);

/// Provides context about failures in [`EventSudo`]
#[doc(alias = "es_sudo_reject_info_t")]
pub struct RejectInfo<'a> {
    /// The raw reference.
    raw: &'a es_sudo_reject_info_t,
}

impl<'a> RejectInfo<'a> {
    /// The sudo plugin that initiated the reject
    #[inline(always)]
    pub fn plugin_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.plugin_name.as_os_str() }
    }
    /// The sudo plugin type that initiated the reject
    #[inline(always)]
    pub fn plugin_type(&self) -> es_sudo_plugin_type_t {
        self.raw.plugin_type
    }
    /// A reason represented by a string for the failure
    #[inline(always)]
    pub fn failure_message(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.failure_message.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for RejectInfo<'_> {}

impl_debug_eq_hash_with_functions!(RejectInfo<'a>; plugin_name, plugin_type, failure_message);
