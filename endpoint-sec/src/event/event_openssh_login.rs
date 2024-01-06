//! [`EventOpensshLogin`]

use std::ffi::OsStr;
use std::net::IpAddr;
use std::str::FromStr;

use endpoint_sec_sys::{
    es_address_type_t, es_event_openssh_login_t, es_openssh_login_result_type_t, uid_t,
};

/// OpenSSH login event.
#[doc(alias = "es_event_openssh_login_t")]
pub struct EventOpensshLogin<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_openssh_login_t,
}

impl<'a> EventOpensshLogin<'a> {
    /// True iff login was successful.
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// Result type for the login attempt.
    #[inline(always)]
    pub fn result_type(&self) -> es_openssh_login_result_type_t {
        self.raw.result_type
    }

    /// Type of source address.
    #[inline(always)]
    pub fn source_address_type(&self) -> es_address_type_t {
        self.raw.source_address_type
    }

    /// Source address of connection.
    #[inline(always)]
    pub fn source_address(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.source_address.as_os_str() }
    }

    /// Username used for login.
    #[inline(always)]
    pub fn username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.username.as_os_str() }
    }

    /// Describes whether or not the UID of the user logged in is available.
    #[inline(always)]
    pub fn has_uid(&self) -> bool {
        self.raw.has_uid
    }

    /// UID of user that was logged in.
    #[inline(always)]
    pub fn uid(&self) -> Option<uid_t> {
        // Safety: access is gated on documented conditions
        self.has_uid().then(|| unsafe { self.raw.anon0.uid })
    }

    /// Source address as an [`IpAddr`] from the standard library, if possible.
    #[inline(always)]
    pub fn source_address_std(&self) -> Option<IpAddr> {
        let sa = self.source_address().to_str()?;
        IpAddr::from_str(sa).ok()
    }
}

// Safety: safe to send acrosss threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventOpensshLogin<'_> {}

impl_debug_eq_hash_with_functions!(
    EventOpensshLogin<'a>;
    success, result_type, source_address_type, source_address, username, has_uid, uid,
);
