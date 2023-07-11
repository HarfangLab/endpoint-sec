//! [`EventListExtAttr`]

use endpoint_sec_sys::es_event_listextattr_t;

use crate::File;

/// List extended attributes of a file event.
#[doc(alias = "es_event_listextattr_t")]
pub struct EventListExtAttr<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_listextattr_t,
}

impl<'a> EventListExtAttr<'a> {
    /// The file for which extended attributes are being retrieved.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventListExtAttr<'_> {}

impl_debug_eq_hash_with_functions!(EventListExtAttr<'a>; target);
