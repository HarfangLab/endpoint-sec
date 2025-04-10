//! [`EventPtyClose`]

use endpoint_sec_sys::{dev_t, es_event_pty_close_t};

/// A pseudoterminal control device is being closed.
#[doc(alias = "es_event_pty_close_t")]
pub struct EventPtyClose<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_pty_close_t,
}

impl EventPtyClose<'_> {
    /// Major and minor numbers of device.
    #[inline(always)]
    pub fn dev(&self) -> dev_t {
        self.raw.dev
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventPtyClose<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventPtyClose<'_> {}

impl_debug_eq_hash_with_functions!(EventPtyClose<'a>; dev);
