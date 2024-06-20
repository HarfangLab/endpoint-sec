//! [`EventLoginLogin`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_login_login_t, uid_t};

/// Authenticated login event from `/usr/bin/login`.
#[doc(alias = "es_event_login_login_t")]
pub struct EventLoginLogin<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_login_login_t,
}

impl<'a> EventLoginLogin<'a> {
    /// True iff login was successful.
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// Optional. Failure message generated.
    #[inline(always)]
    pub fn failure_message(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.failure_message.as_os_str() }
    }

    /// Username used for login.
    #[inline(always)]
    pub fn username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.username.as_os_str() }
    }

    /// Describes whether or not the uid of the user logged in is available.
    #[inline(always)]
    pub fn has_uid(&self) -> bool {
        self.raw.has_uid
    }

    /// UID of user that was logged in.
    #[inline(always)]
    pub fn uid(&self) -> Option<uid_t> {
        // Safety: access is gated on documented conditions
        #[allow(clippy::unnecessary_lazy_evaluations)]
        self.has_uid().then(|| unsafe { self.raw.anon0.uid })
    }
}

// Safety: safe to send acrosss threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventLoginLogin<'_> {}

impl_debug_eq_hash_with_functions!(
    EventLoginLogin<'a>;
    success, failure_message, username, has_uid, uid,
);
