//! [`EventMmap`]

use endpoint_sec_sys::es_event_mmap_t;

use crate::File;

/// Memory map a file event.
#[doc(alias = "es_event_mmap_t")]
pub struct EventMmap<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_mmap_t,
}

impl<'a> EventMmap<'a> {
    ///  The protection (region accessibility) value.
    #[inline(always)]
    pub fn protection(&self) -> i32 {
        self.raw.protection
    }

    /// The maximum allowed protection value the operating system will respect.
    #[inline(always)]
    pub fn max_protection(&self) -> i32 {
        self.raw.max_protection
    }

    /// The type and attributes of the mapped file.
    #[inline(always)]
    pub fn flags(&self) -> i32 {
        self.raw.flags
    }

    /// The offset into the source file that will be mapped.
    #[inline(always)]
    pub fn file_pos(&self) -> u64 {
        self.raw.file_pos
    }

    /// The file system object being mapped.
    #[inline(always)]
    pub fn source(&self) -> File<'_> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventMmap<'_> {}

impl_debug_eq_hash_with_functions!(EventMmap<'a>; protection, max_protection, flags, file_pos, source);
