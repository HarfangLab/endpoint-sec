//! [`EventExchangeData`]

use endpoint_sec_sys::es_event_exchangedata_t;

use crate::File;

/// Exchange data atomically between two files event.
#[doc(alias = "es_event_exchangedata_t")]
pub struct EventExchangeData<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_exchangedata_t,
}

impl<'a> EventExchangeData<'a> {
    /// The first file to be exchanged.
    #[inline(always)]
    pub fn file1(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.file1() })
    }

    /// The second file to be exchanged.
    #[inline(always)]
    pub fn file2(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.file2() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventExchangeData<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventExchangeData<'_> {}

impl_debug_eq_hash_with_functions!(EventExchangeData<'a>; file1, file2);
