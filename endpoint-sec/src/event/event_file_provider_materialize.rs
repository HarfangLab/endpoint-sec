//! [`EventFileProviderMaterialize`]

use endpoint_sec_sys::es_event_file_provider_materialize_t;

use crate::{AuditToken, File, Process};

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
    pub fn instigator(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.instigator()? };
        Some(Process::new(process, self.version))
    }

    /// Audit token of the process that instigated this event.
    pub fn instigator_token(&self) -> AuditToken {
        #[cfg(feature = "macos_15_0_0")]
        if self.version >= 8 {
            return AuditToken(self.raw.instigator_token)
        }

        // On old versions, the process was always non-null, and we can get
        // its token easily.
        self.instigator().unwrap().audit_token()
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

impl_debug_eq_hash_with_functions!(EventFileProviderMaterialize<'a> with version; instigator, instigator_token, source, target);
