//! [`EventLwSessionLogin`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_lw_session_login_t, es_graphical_session_id_t};

/// LoginWindow has logged in a user.
#[doc(alias = "es_event_lw_session_login_t")]
pub struct EventLwSessionLogin<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_lw_session_login_t,
}

impl<'a> EventLwSessionLogin<'a> {
    /// Short username of the user.
    #[inline(always)]
    pub fn username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.username.as_os_str() }
    }

    /// Graphical session id of the session.
    #[inline(always)]
    pub fn graphical_session_id(&self) -> es_graphical_session_id_t {
        self.raw.graphical_session_id
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventLwSessionLogin<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventLwSessionLogin<'_> {}

impl_debug_eq_hash_with_functions!(EventLwSessionLogin<'a>; username, graphical_session_id);
