//! [`EventClose`]

use endpoint_sec_sys::es_event_close_t;

use crate::File;

///  Close a file descriptor event.
#[doc(alias = "es_event_close_t")]
pub struct EventClose<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_close_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventClose<'a> {
    /// true if the target file being closed has been modified.
    #[inline(always)]
    pub fn modified(&self) -> bool {
        self.raw.modified
    }

    /// The file that is being closed.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }

    /// If `true`, at some point in the lifetime of the target file vnode it was mapped into a
    /// process as writable.
    #[cfg(feature = "macos_13_0_0")]
    #[inline(always)]
    pub fn was_mapped_writable(&self) -> Option<bool> {
        if self.version < 6 {
            return None;
        }
        // Safety: 'a tied to self, object obtained through ES, we checked the version first
        Some(unsafe { self.raw.anon0.was_mapped_writable })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventClose<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventClose<'_> {}

impl_debug_eq_hash_with_functions!(
    EventClose<'a> with version;
    modified,
    target,
    #[cfg(feature = "macos_13_0_0")] was_mapped_writable,
);
