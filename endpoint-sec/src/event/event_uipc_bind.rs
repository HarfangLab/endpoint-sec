//! [`EventUipcBind`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_uipc_bind_t, mode_t};

use crate::File;

/// A UNIX-domain socket is about to be bound to a path.
#[doc(alias = "es_event_uipc_bind_t")]
pub struct EventUipcBind<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_uipc_bind_t,
}

impl<'a> EventUipcBind<'a> {
    /// Describes the directory the socket file is created in.
    #[inline(always)]
    pub fn dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.dir() })
    }

    /// The filename of the socket file.
    #[inline(always)]
    pub fn filename(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.filename.as_os_str() }
    }

    /// Mode of the socket file.
    #[inline(always)]
    pub fn mode(&self) -> mode_t {
        self.raw.mode
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventUipcBind<'_> {}

impl_debug_eq_hash_with_functions!(EventUipcBind<'a>; dir, filename, mode);
