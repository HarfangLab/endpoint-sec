//! [`EventSetAttrlist`]

use endpoint_sec_sys::{attrlist, es_event_setattrlist_t};

use crate::File;

/// Set file system attributes event.
#[doc(alias = "es_event_setattrlist_t")]
pub struct EventSetAttrlist<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setattrlist_t,
}

impl<'a> EventSetAttrlist<'a> {
    /// The attributes that will be modified.
    #[inline(always)]
    pub fn attrlist(&self) -> attrlist {
        self.raw.attrlist
    }

    /// The file for which attributes will be modified.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetAttrlist<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSetAttrlist<'_> {}

impl_debug_eq_hash_with_functions!(EventSetAttrlist<'a>; attrlist, target);
