//! [`EventOdGroupRemove`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_od_group_remove_t;

use crate::{AuditToken, OdMemberId, Process};

/// Notification that a member was removed to a group.
///
/// This event does not indicate that a member was actually removed. For example when removing a
/// user from a group they are not a member of.
#[doc(alias = "es_event_od_group_remove_t")]
pub struct EventOdGroupRemove<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_group_remove_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdGroupRemove<'a> {
    /// Process that instigated operation (XPC caller).
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

    /// Result code for the operation.
    #[inline(always)]
    pub fn error_code(&self) -> i32 {
        self.raw.error_code
    }

    /// The group to which the member was removed.
    #[inline(always)]
    pub fn group_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.group_name.as_os_str() }
    }

    /// The identity of the member removed.
    #[inline(always)]
    pub fn member(&self) -> OdMemberId<'a> {
        OdMemberId {
            // Safety: 'a tied to self, object obtained through ES
            raw: unsafe { self.raw.member.as_ref() },
        }
    }

    /// OD node being mutated.
    ///
    /// Typically one of "/Local/Default", "/LDAPv3/<server>" or "/Active Directory/<domain>".
    #[inline(always)]
    pub fn node_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.node_name.as_os_str() }
    }

    /// Optional. If node_name is "/Local/Default", this is, the path of the database against which
    /// OD is authenticating.
    #[inline(always)]
    pub fn db_path(&self) -> Option<&'a OsStr> {
        if self.node_name() == OsStr::new("/Local/Default") {
            // Safety: 'a tied to self, object obtained through ES
            Some(unsafe { self.raw.db_path.as_os_str() })
        } else {
            None
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventOdGroupRemove<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventOdGroupRemove<'_> {}

impl_debug_eq_hash_with_functions!(EventOdGroupRemove<'a> with version; instigator, instigator_token, error_code, group_name, member, node_name, db_path);
