//! Mute types.

use std::ffi::OsString;

use endpoint_sec_sys::{es_event_type_t, es_mute_path_type_t};

use crate::AuditToken;

/// See [`endpoint_sec_sys::es_muted_path_t`]
#[doc(alias = "es_muted_path_t")]
#[derive(Debug, Clone)]
pub struct MutedPath {
    /// Indicates if the path is a prefix or a literal
    pub ty: es_mute_path_type_t,
    /// Event types for which the path is muted
    pub events: Vec<es_event_type_t>,
    /// Muted path
    pub path: OsString,
}

static_assertions::assert_impl_all!(MutedPath: Send);

/// See [`endpoint_sec_sys::es_muted_process_t`]
#[doc(alias = "es_muted_process_t")]
#[derive(Debug, Clone)]
pub struct MutedProcess {
    /// Audit token of the muted process
    pub audit_token: AuditToken,
    /// Events for which the process is muted
    pub events: Vec<es_event_type_t>,
}

static_assertions::assert_impl_all!(MutedProcess: Send);
