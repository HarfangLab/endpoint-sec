//! [`EventSetFlags`]

use endpoint_sec_sys::es_event_setflags_t;

use crate::File;

/// Modify file flags information event.
#[doc(alias = "es_event_setflags_t")]
pub struct EventSetFlags<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setflags_t,
}

impl<'a> EventSetFlags<'a> {
    /// The desired new flags.
    #[inline(always)]
    pub fn flags(&self) -> u32 {
        self.raw.flags
    }

    /// The file for which flags information will be modified.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetFlags<'_> {}

impl_debug_eq_hash_with_functions!(EventSetFlags<'a>; flags, target);
