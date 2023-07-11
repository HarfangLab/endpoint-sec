//! [`EventOpen`]

use endpoint_sec_sys::es_event_open_t;

use crate::File;

/// File system object open event.
#[doc(alias = "es_event_open_t")]
pub struct EventOpen<'a> {
    /// Raw event
    pub(super) raw: &'a es_event_open_t,
}

impl<'a> EventOpen<'a> {
    /// The desired **kernel** flags to be used when opening the file.
    #[inline(always)]
    pub fn fflag(&self) -> i32 {
        self.raw.fflag
    }

    /// The file that will be opened.
    #[inline(always)]
    pub fn file(&self) -> File<'_> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.file() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventOpen<'_> {}

impl_debug_eq_hash_with_functions!(EventOpen<'a>; fflag, file);
