//! [`EventAuthorizationJudgement`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_authorization_result_t, es_authorization_rule_class_t, es_event_authorization_judgement_t};

use crate::Process;

/// Notification that a process had it's right petition judged
#[doc(alias = "es_event_authorization_judgement_t")]
pub struct EventAuthorizationJudgement<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_authorization_judgement_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventAuthorizationJudgement<'a> {
    /// Process that submitted the petition (XPC caller)
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator.as_ref() }, self.version)
    }

    /// Process that created the petition
    #[inline(always)]
    pub fn petitioner(&self) -> Option<Process<'a>> {
        Some(Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.petitioner.as_ref()? },
            self.version,
        ))
    }

    /// The overall result of the petition. 0 indicates success.
    ///
    /// Possible return codes are defined in Security framework "Authorization/Authorization.h"
    #[inline(always)]
    pub fn return_code(&self) -> i32 {
        self.raw.return_code
    }

    /// Number of results.
    #[inline(always)]
    pub fn result_count(&self) -> usize {
        self.raw.result_count
    }

    /// Iterator over the results
    #[inline(always)]
    pub fn rights<'event>(&'event self) -> AuthorizationJudgementResults<'event, 'a> {
        AuthorizationJudgementResults::new(self)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthorizationJudgement<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventAuthorizationJudgement<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthorizationJudgement<'a> with version; instigator, petitioner, return_code, result_count);

/// Describes, for a single right, the class of that right and if it was granted
#[doc(alias = "es_authorization_result_t")]
pub struct AuthorizationResult<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_authorization_result_t,
}

impl<'a> AuthorizationResult<'a> {
    /// The name of the right being considered
    #[inline(always)]
    pub fn right_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.right_name.as_os_str() }
    }

    /// The class of the right being considered
    ///
    /// The rule class determines how the operating system determines if it should be granted or not
    #[inline(always)]
    pub fn rule_class(&self) -> es_authorization_rule_class_t {
        self.raw.rule_class
    }
    /// Indicates if the right was granted or not
    #[inline(always)]
    pub fn granted(&self) -> bool {
        self.raw.granted
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for AuthorizationResult<'_> {}

impl_debug_eq_hash_with_functions!(AuthorizationResult<'a>; right_name, rule_class, granted);

/// Read the `idx` result of `raw`
///
/// # Safety
///
/// Must be called with a valid event for which `idx` is in range `0..raw.result_count`
unsafe fn read_nth_result(raw: &es_event_authorization_judgement_t, idx: usize) -> *const es_authorization_result_t {
    raw.results.add(idx).cast_const()
}

/// See [`super::as_os_str()`] for lifetime and safety docs
unsafe fn make_result<'a>(result: *const es_authorization_result_t) -> AuthorizationResult<'a> {
    assert!(!result.is_null());
    AuthorizationResult {
        raw: unsafe { &*result },
    }
}

make_event_data_iterator!(
    EventAuthorizationJudgement;
    /// Iterator over the rights of an [`EventAuthorizationJudgement`]
    AuthorizationJudgementResults with result_count (usize);
    AuthorizationResult<'raw>;
    read_nth_result,
    make_result,
);
