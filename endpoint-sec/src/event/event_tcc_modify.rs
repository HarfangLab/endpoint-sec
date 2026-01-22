//! [`EventTccModify`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_tcc_modify_t, es_tcc_identity_type_t, es_tcc_event_type_t, es_tcc_authorization_right_t, es_tcc_authorization_reason_t};

use crate::{AuditToken, Process};

/// TCC Modification Event.
///
/// Occurs when a TCC permission is granted or revoked.
///
/// Note: This event type does not support caching.
#[doc(alias = "es_event_tcc_modify_t")]
pub struct EventTccModify<'a> {
    /// Raw event
    pub(super) raw: &'a es_event_tcc_modify_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventTccModify<'a> {
    /// The TCC service for which permissions are being modified.
    #[inline(always)]
    pub fn service(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.service.as_os_str() }
    }

    /// The identity of the application that is the subject of the permission.
    #[inline(always)]
    pub fn identity(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.identity.as_os_str() }
    }

    /// The identity type of the application string (Bundle ID, path, etc).
    #[inline(always)]
    pub fn identity_type(&self) -> es_tcc_identity_type_t {
        self.raw.identity_type
    }

    /// The type of TCC modification event (Grant/Revoke etc)
    #[inline(always)]
    pub fn update_type(&self) -> es_tcc_event_type_t {
        self.raw.update_type
    }

    /// Audit token of the instigator of the modification.
    #[inline(always)]
    pub fn instigator_token(&self) -> AuditToken {
        AuditToken(self.raw.instigator_token)
    }

    /// (Optional) The process information for the instigator.
    #[inline(always)]
    pub fn instigator(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.instigator()? };
        Some(Process::new(process, self.version))
    }

    /// (Optional) Audit token of the responsible process for the modification.
    #[inline(always)]
    pub fn responsible_token(&self) -> Option<AuditToken> {
        let token = unsafe { self.raw.responsible_token()? };
        Some(AuditToken(*token))
    }

    /// (Optional) The process information for the responsible process.
    #[inline(always)]
    pub fn responsible(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.responsible()? };
        Some(Process::new(process, self.version))
    }

    /// The resulting TCC permission of the operation/modification.
    #[inline(always)]
    pub fn right(&self) -> es_tcc_authorization_right_t {
        self.raw.right
    }

    /// The reason the TCC permissions were updated.
    #[inline(always)]
    pub fn reason(&self) -> es_tcc_authorization_reason_t {
        self.raw.reason
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventTccModify<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventTccModify<'_> {}

impl_debug_eq_hash_with_functions!(EventTccModify<'a>; service, identity, identity_type, update_type, instigator_token, instigator, responsible_token, responsible, right, reason);
