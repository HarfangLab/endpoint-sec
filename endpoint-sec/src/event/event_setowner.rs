//! [`EventSetOwner`]

use endpoint_sec_sys::{es_event_setowner_t, gid_t, uid_t};

use crate::File;

/// Modify file owner information.
#[doc(alias = "es_event_setowner_t")]
pub struct EventSetOwner<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setowner_t,
}

impl<'a> EventSetOwner<'a> {
    /// The desired new UID.
    #[inline(always)]
    pub fn uid(&self) -> uid_t {
        self.raw.uid
    }

    /// The desired new GID.
    #[inline(always)]
    pub fn gid(&self) -> gid_t {
        self.raw.gid
    }

    /// The file for which owner information will be modified.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetOwner<'_> {}

impl_debug_eq_hash_with_functions!(EventSetOwner<'a>; uid, gid, target);
