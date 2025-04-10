//! [`EventStat`]

use endpoint_sec_sys::es_event_stat_t;

use crate::File;

/// View stat information of a file event.
#[doc(alias = "es_event_stat_t")]
pub struct EventStat<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_stat_t,
}

impl<'a> EventStat<'a> {
    /// The file for which stat information will be retrieved.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventStat<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventStat<'_> {}

impl_debug_eq_hash_with_functions!(EventStat<'a>; target);
