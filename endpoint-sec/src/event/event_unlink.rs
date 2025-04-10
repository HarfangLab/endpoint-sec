//! [`EventUnlink`]

use endpoint_sec_sys::es_event_unlink_t;

use crate::File;

/// Unlink a file system object event.
#[doc(alias = "es_event_unlink_t")]
pub struct EventUnlink<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_unlink_t,
}

impl<'a> EventUnlink<'a> {
    /// The object that will be removed.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }

    /// The parent directory of the `target` file system object.
    #[inline(always)]
    pub fn parent_dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.parent_dir() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventUnlink<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventUnlink<'_> {}

impl_debug_eq_hash_with_functions!(EventUnlink<'a>; target, parent_dir);
