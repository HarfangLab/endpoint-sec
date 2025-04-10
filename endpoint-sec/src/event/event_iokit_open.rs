//! [`EventIoKitOpen`]

use std::ffi::OsStr;

use endpoint_sec_sys::es_event_iokit_open_t;

/// Open a connection to an I/O Kit IOService event.
#[doc(alias = "es_event_iokit_open_t")]
pub struct EventIoKitOpen<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_iokit_open_t,
}

impl<'a> EventIoKitOpen<'a> {
    /// A constant specifying the type of connection to be created, interpreted only by the IOService's family.
    ///
    /// **Note**: This corresponds to the type argument to `IOServiceOpen()`.
    #[inline(always)]
    pub fn user_client_type(&self) -> u32 {
        self.raw.user_client_type
    }

    /// The name of the new object linked to the source file.
    #[inline(always)]
    pub fn user_client_class(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.user_client_class.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventIoKitOpen<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventIoKitOpen<'_> {}

impl_debug_eq_hash_with_functions!(EventIoKitOpen<'a>; user_client_type, user_client_class);
