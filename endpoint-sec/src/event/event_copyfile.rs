//! [`EventCopyFile`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_copyfile_t, mode_t};

use crate::File;

/// Copy a file using the `copyfile()` system call.
///
/// Note: Not to be confused with `copyfile(3)`.
///
/// Note: Prior to macOS 12.0, the copyfile syscall fired open, unlink and auth create events,
/// but no notify create, nor write or close events.
#[doc(alias = "es_event_copyfile_t")]
pub struct EventCopyFile<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_copyfile_t,
}

impl<'a> EventCopyFile<'a> {
    /// The file that will be copied.
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// The file that will be overwritten by the operation, if any.
    #[inline(always)]
    pub fn target_file(&self) -> Option<File<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.target_file() }.map(File::new)
    }

    /// The directory into which the [`Self::source()`] file will be copied.
    #[inline(always)]
    pub fn target_dir(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target_dir() })
    }

    /// Name of the new file to which [`Self::source()`] will be copied.
    #[inline(always)]
    pub fn target_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.target_name.as_os_str() }
    }

    /// Corresponds to mode argument of the `copyfile()` syscall.
    #[inline(always)]
    pub fn mode(&self) -> mode_t {
        self.raw.mode
    }

    /// Corresponds to flags argument of the `copyfile()` syscall.
    #[inline(always)]
    pub fn flags(&self) -> i32 {
        self.raw.flags
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventCopyFile<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventCopyFile<'_> {}

impl_debug_eq_hash_with_functions!(EventCopyFile<'a>; source, target_file, target_dir, target_name, mode, flags);
