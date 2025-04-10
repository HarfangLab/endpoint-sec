//! [`EventSetAcl`]

use endpoint_sec_sys::{acl_t, es_event_setacl_t, es_set_or_clear_t};

use crate::File;

/// Set a file ACL.
#[doc(alias = "es_event_setacl_t")]
pub struct EventSetAcl<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setacl_t,
}

impl<'a> EventSetAcl<'a> {
    /// File whose ACL is being set.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }

    /// Whether the ACL on the [`target`][Self::target()] is being set or cleared
    #[inline(always)]
    pub fn set_or_clear(&self) -> es_set_or_clear_t {
        self.raw.set_or_clear
    }

    /// The [`acl_t`] structure to be used by various acl(3) functions.
    ///
    /// Only available in the `ES_SET` case.
    ///
    /// Note: the provided acl cannot be used directly with the acl(3) functions, see documentation
    /// on the original type, [`es_event_setacl_t`] for details.
    #[inline(always)]
    pub fn set(&self) -> Option<&'a acl_t> {
        // Safety: the pointer is behind a lifetime tied to `self`
        unsafe { self.raw.acl() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetAcl<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventSetAcl<'_> {}

impl_debug_eq_hash_with_functions!(EventSetAcl<'a>; target, set_or_clear, set);
