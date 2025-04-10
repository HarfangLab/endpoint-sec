//! [`EventFileProviderMaterialize`]

use endpoint_sec_sys::es_event_file_provider_materialize_t;

use crate::{File, Process};

/// Materialize a file via the FileProvider framework event.
#[doc(alias = "es_event_file_provider_materialize_t")]
pub struct EventFileProviderMaterialize<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_file_provider_materialize_t,

    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventFileProviderMaterialize<'a> {
    /// The process that instigated the materialization.
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator() }, self.version)
    }

    /// The staged file that has been materialized
    #[inline(always)]
    pub fn source(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.source() })
    }

    /// The destination of the staged source file.
    #[inline(always)]
    pub fn target(&self) -> File<'a> {
        // Safety: 'a tied to self, object obtained through ES
        File::new(unsafe { self.raw.target() })
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventFileProviderMaterialize<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventFileProviderMaterialize<'_> {}

impl_debug_eq_hash_with_functions!(EventFileProviderMaterialize<'a> with version; instigator, source, target);
