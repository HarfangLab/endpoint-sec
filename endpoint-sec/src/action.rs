//! Actions associated with a [`Message`][crate::Message].

use endpoint_sec_sys::{es_auth_result_t, es_event_id_t, es_result_t, es_result_type_t};

/// When a [`Message`][crate::Message] is received, it is associated with an `Action`
#[doc(alias = "es_event_id_t")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum Action {
    /// For `AUTH` events, it is the opaque ID that must be supplied when responding
    Auth(es_event_id_t),
    /// For `NOTIFY` events, describes the result of the action
    Notify(ActionResult),
}

static_assertions::assert_impl_all!(Action: Send);

/// Result of the ES subsystem authorization process.
///
/// See also [`Action`].
#[doc(alias = "es_result_t")]
#[doc(alias = "es_result_type_t")]
#[doc(alias = "es_auth_result_t")]
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub enum ActionResult {
    /// Result of an `AUTH` action
    Auth(es_auth_result_t),
    /// Flags resulting of an action
    Flags(u32),
}

impl ActionResult {
    /// Build [`Self`] from the raw result
    pub(crate) fn from_raw(r: es_result_t) -> Option<Self> {
        match r.result_type {
            // Safety: we just checked the `result_type` member
            es_result_type_t::ES_RESULT_TYPE_AUTH => Some(Self::Auth(unsafe { r.result.auth })),
            // Safety: we just checked the `result_type` member
            es_result_type_t::ES_RESULT_TYPE_FLAGS => Some(Self::Flags(unsafe { r.result.flags })),
            _ => None,
        }
    }
}

static_assertions::assert_impl_all!(ActionResult: Send);
