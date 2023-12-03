//! [`EventOdModifyPassword`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_od_modify_password_t, es_od_account_type_t};

use crate::Process;

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
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator.as_ref() }, self.version)
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

impl_debug_eq_hash_with_functions!(EventOdModifyPassword<'a> with version; instigator, error_code, account_type, account_name, node_name, db_path);
