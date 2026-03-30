//! [`EventOdModifyPassword`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_od_modify_password_t, es_od_account_type_t};

use crate::{AuditToken, Process};

/// Notification that an account had its password modified.
#[doc(alias = "es_event_od_modify_password_t")]
pub struct EventOdModifyPassword<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_modify_password_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdModifyPassword<'a> {
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

    /// The type of the account for which the password was modified.
    #[inline(always)]
    pub fn account_type(&self) -> es_od_account_type_t {
        self.raw.account_type
    }

    /// The name of the account for which the password was modified.
    #[inline(always)]
    pub fn account_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.account_name.as_os_str() }
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
unsafe impl Send for EventOdModifyPassword<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventOdModifyPassword<'_> {}

impl_debug_eq_hash_with_functions!(EventOdModifyPassword<'a> with version; instigator, instigator_token, error_code, account_type, account_name, node_name, db_path);
