//! [`EventMprotect`]

use endpoint_sec_sys::es_event_mprotect_t;

/// Control protection of pages event.
#[doc(alias = "es_event_mprotect_t")]
pub struct EventMprotect<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_mprotect_t,
}

impl EventMprotect<'_> {
    ///  The desired new protection value.
    #[inline(always)]
    pub fn protection(&self) -> i32 {
        self.raw.protection
    }

    /// The base address to which the protection value will apply.
    #[inline(always)]
    pub fn address(&self) -> usize {
        self.raw.address as usize
    }

    /// The size of the memory region the protection value will apply.
    #[inline(always)]
    pub fn size(&self) -> usize {
        self.raw.size as usize
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventMprotect<'_> {}

impl_debug_eq_hash_with_functions!(EventMprotect<'a>; protection, address, size);
