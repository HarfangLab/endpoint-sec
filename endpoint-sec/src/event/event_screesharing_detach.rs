//! [`EventScreensharingDetach`]

use std::ffi::OsStr;
use std::net::IpAddr;
use std::str::FromStr;

use endpoint_sec_sys::{es_address_type_t, es_event_screensharing_detach_t, es_graphical_session_id_t};

/// Screen Sharing has detached from a graphical session..
#[doc(alias = "es_event_screensharing_detach_t")]
pub struct EventScreensharingDetach<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_screensharing_detach_t,
}

impl<'a> EventScreensharingDetach<'a> {
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
unsafe impl Send for EventScreensharingDetach<'_> {}

impl_debug_eq_hash_with_functions!(
    EventScreensharingDetach<'a>;
    source_address_type, source_address, viewer_appleid, graphical_session_id,
);
