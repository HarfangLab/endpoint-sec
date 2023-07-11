//! [`EventFcntl`]

use endpoint_sec_sys::es_event_fcntl_t;

use crate::File;

/// File control event.
#[doc(alias = "es_event_fcntl_t")]
pub struct EventFcntl<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_fcntl_t,
}

impl<'a> EventFcntl<'a> {
    ///  The target file on which the file control command will be performed.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }

    /// The cmd argument given to fcntl(2).
    #[inline(always)]
    pub fn cmd(&self) -> i32 {
        self.raw.cmd
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventFcntl<'_> {}

impl_debug_eq_hash_with_functions!(EventFcntl<'a>; target, cmd);
