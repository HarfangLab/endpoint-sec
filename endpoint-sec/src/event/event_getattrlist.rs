//! [`EventGetAttrlist`]

use endpoint_sec_sys::{attrlist, es_event_getattrlist_t};

use crate::File;

/// Retrieve file system attributes event.
#[doc(alias = "es_event_getattrlist_t")]
pub struct EventGetAttrlist<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_getattrlist_t,
}

impl<'a> EventGetAttrlist<'a> {
    /// The attributes that will be retrieved.
    #[inline(always)]
    pub fn attrlist(&self) -> attrlist {
        self.raw.attrlist
    }

    /// The file for which attributes will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventGetAttrlist<'_> {}

impl_debug_eq_hash_with_functions!(EventGetAttrlist<'a>; target, attrlist);
