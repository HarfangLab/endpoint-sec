//! [`EventOpensshLogout`]

use std::ffi::OsStr;
use std::net::IpAddr;
use std::str::FromStr;

use endpoint_sec_sys::{es_address_type_t, es_event_openssh_logout_t, uid_t};

/// OpenSSH logout event.
#[doc(alias = "es_event_openssh_logout_t")]
pub struct EventOpensshLogout<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_openssh_logout_t,
}

impl<'a> EventOpensshLogout<'a> {
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

    /// Username which got logged out.
    #[inline(always)]
    pub fn username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.username.as_os_str() }
    }

    /// UID of user that was logged out.
    #[inline(always)]
    pub fn uid(&self) -> uid_t {
        self.raw.uid
    }

    /// Source address as an [`IpAddr`] from the standard library, if possible.
    #[inline(always)]
    pub fn source_address_std(&self) -> Option<IpAddr> {
        let sa = self.source_address().to_str()?;
        IpAddr::from_str(sa).ok()
    }
}

// Safety: safe to send acrosss threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventOpensshLogout<'_> {}

impl_debug_eq_hash_with_functions!(
    EventOpensshLogout<'a>;
    source_address_type, source_address, username, uid,
);
