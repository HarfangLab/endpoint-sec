//! [`EventLoginLogout`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_login_logout_t, uid_t};

/// Authenticated logout event from `/usr/bin/login`.
#[doc(alias = "es_event_login_logout_t")]
pub struct EventLoginLogout<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_login_logout_t,
}

impl<'a> EventLoginLogout<'a> {
    /// Username used for login.
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
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventLoginLogout<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventLoginLogout<'_> {}

impl_debug_eq_hash_with_functions!(EventLoginLogout<'a>; username, uid);
