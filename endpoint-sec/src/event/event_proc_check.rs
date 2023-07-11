//! [`EventProcCheck`]

use endpoint_sec_sys::{es_event_proc_check_t, es_proc_check_type_t};

use crate::Process;

/// Access control check for retrieving process information.
#[doc(alias = "es_event_proc_check_t")]
pub struct EventProcCheck<'a> {
    /// Raw reference
    pub(crate) raw: &'a es_event_proc_check_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventProcCheck<'a> {
    /// Process for which the access will be checked.
    #[inline(always)]
    pub fn target(&self) -> Option<Process<'a>> {
        Some(Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.target() }?,
            self.version,
        ))
    }

    /// Type of call number used to check the access on the target process.
    #[inline(always)]
    pub fn type_(&self) -> es_proc_check_type_t {
        self.raw.type_
    }

    /// Flavor used to check the access on the target process.
    #[inline(always)]
    pub fn flavor(&self) -> i32 {
        self.raw.flavor
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventProcCheck<'_> {}

impl_debug_eq_hash_with_functions!(EventProcCheck<'a> with version; target, type_, flavor);
