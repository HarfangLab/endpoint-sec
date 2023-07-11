//! [`EventSearchFs`]

use endpoint_sec_sys::{attrlist, es_event_searchfs_t};

use crate::File;

/// Access control check for searching a volume or a mounted file system event.
#[doc(alias = "es_event_searchfs_t")]
pub struct EventSearchFs<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_searchfs_t,
}

impl<'a> EventSearchFs<'a> {
    /// The attributes that will be used to do the search.
    #[inline(always)]
    pub fn attrlist(&self) -> attrlist {
        self.raw.attrlist
    }

    /// The volume whose contents will be searched.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSearchFs<'_> {}

impl_debug_eq_hash_with_functions!(EventSearchFs<'a>; attrlist, target);
