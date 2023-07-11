//! [`EventSetMode`]

use endpoint_sec_sys::{es_event_setmode_t, mode_t};

use crate::File;

/// Modify file mode event.
#[doc(alias = "es_event_setmode_t")]
pub struct EventSetMode<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_setmode_t,
}

impl<'a> EventSetMode<'a> {
    /// The desired new mode.
    #[inline(always)]
    pub fn mode(&self) -> mode_t {
        self.raw.mode
    }

    /// The file for which mode information will be modified.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventSetMode<'_> {}

impl_debug_eq_hash_with_functions!(EventSetMode<'a>; mode, target);
