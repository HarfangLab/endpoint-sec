//! [`EventChdir`]

use endpoint_sec_sys::es_event_chdir_t;

use crate::File;

/// Change directories event.
#[doc(alias = "es_event_chdir_t")]
pub struct EventChdir<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_chdir_t,
}

impl<'a> EventChdir<'a> {
    /// The desired new current working directory.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventChdir<'_> {}

impl_debug_eq_hash_with_functions!(EventChdir<'a>; target);
