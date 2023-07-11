//! [`EventScreensharingAttach`]

use std::ffi::OsStr;
use std::net::IpAddr;
use std::str::FromStr;

use endpoint_sec_sys::{es_address_type_t, es_event_screensharing_attach_t, es_graphical_session_id_t};

/// Screen Sharing has attached from a graphical session..
#[doc(alias = "es_event_screensharing_attach_t")]
pub struct EventScreensharingAttach<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_screensharing_attach_t,
}

impl<'a> EventScreensharingAttach<'a> {
    /// True iff remediation was successful.
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// Type of source address.
    #[inline(always)]
    pub fn source_address_type(&self) -> es_address_type_t {
        self.raw.source_address_type
    }

    /// Optional. Source address of connection, or empty. Depending on the transport used, the
    /// source address may or may not be available.
    #[inline(always)]
    pub fn source_address(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.source_address.as_os_str() }
    }

    /// Optional. For screen sharing initiated using an Apple ID (e.g., from Messages or FaceTime),
    /// this is the viewer's (client's) Apple ID. It is not necessarily the Apple ID that invited
    /// the screen sharing. Empty if unavailable.
    #[inline(always)]
    pub fn viewer_appleid(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.viewer_appleid.as_os_str() }
    }

    /// Type of authentication.
    #[inline(always)]
    pub fn authentication_type(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.authentication_type.as_os_str() }
    }

    /// Optional. Username used for authentication to Screen Sharing. `NULL` if authentication type
    /// doesn't use an username (e.g. simple VNC password).
    #[inline(always)]
    pub fn authentication_username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.authentication_username.as_os_str() }
    }

    /// Optional. Username of the loginwindow session if available, `NULL` otherwise.
    #[inline(always)]
    pub fn session_username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.session_username.as_os_str() }
    }

    /// True iff there was an existing user session.
    #[inline(always)]
    pub fn existing_session(&self) -> bool {
        self.raw.existing_session
    }

    /// Graphical session id of the screen shared.
    #[inline(always)]
    pub fn graphical_session_id(&self) -> es_graphical_session_id_t {
        self.raw.graphical_session_id
    }

    /// Source address as an [`IpAddr`] from the standard library, if possible.
    #[inline(always)]
    pub fn source_address_std(&self) -> Option<IpAddr> {
        let sa = self.source_address().to_str()?;
        IpAddr::from_str(sa).ok()
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventScreensharingAttach<'_> {}

impl_debug_eq_hash_with_functions!(
    EventScreensharingAttach<'a>;
    success, source_address_type, source_address, viewer_appleid, authentication_type,
    authentication_username, session_username, existing_session, graphical_session_id,
);
