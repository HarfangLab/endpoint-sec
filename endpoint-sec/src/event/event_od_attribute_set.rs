//! [`EventOdAttributeSet`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_od_attribute_set_t, es_od_record_type_t, es_string_token_t};

use crate::{AuditToken, Process};

/// Notification that an attribute is being set.
///
/// Attributes conceptually have the type `Map String (Set String)`.
/// Each OD record has a Map of attribute name to Set of attribute value.
/// When an attribute value is added, it is inserted into the set of values for that name.
///
/// The new set of attribute values may be empty.
#[doc(alias = "es_event_od_attribute_set_t")]
pub struct EventOdAttributeSet<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_attribute_set_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdAttributeSet<'a> {
    /// Process that instigated operation (XPC caller).
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
            return AuditToken(self.raw.instigator_token);
        }

        // On old versions, the process was always non-null, and we can get
        // its token easily.
        self.instigator().unwrap().audit_token()
    }

    /// Result code for the operation.
    #[inline(always)]
    pub fn error_code(&self) -> i32 {
        self.raw.error_code
    }

    /// The type of the record for which the attribute is being set.
    #[inline(always)]
    pub fn record_type(&self) -> es_od_record_type_t {
        self.raw.record_type
    }

    /// The name of the record for which the attribute is being set.
    #[inline(always)]
    pub fn record_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.record_name.as_os_str() }
    }

    /// The name of the attribute that was set.
    #[inline(always)]
    pub fn attribute_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.attribute_name.as_os_str() }
    }

    /// The size of attribute_value_array.
    #[inline(always)]
    pub fn attribute_value_count(&self) -> usize {
        self.raw.attribute_value_count
    }

    /// Iterator over the attribute values that were set.
    #[inline(always)]
    pub fn attribute_values<'s>(&'s self) -> AttributeValues<'s, 'a> {
        AttributeValues::new(self)
    }

    /// OD node being mutated.
    ///
    /// Typically one of "/Local/Default", "/LDAPv3/<server>" or "/Active Directory/<domain>".
    #[inline(always)]
    pub fn node_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.node_name.as_os_str() }
    }

    /// Optional. If node_name is "/Local/Default", this is, the path of the database against which
    /// OD is authenticating.
    #[inline(always)]
    pub fn db_path(&self) -> Option<&'a OsStr> {
        if self.node_name() == OsStr::new("/Local/Default") {
            // Safety: 'a tied to self, object obtained through ES
            Some(unsafe { self.raw.db_path.as_os_str() })
        } else {
            None
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventOdAttributeSet<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventOdAttributeSet<'_> {}

impl_debug_eq_hash_with_functions!(EventOdAttributeSet<'a> with version; instigator, instigator_token, error_code, record_type, record_name, attribute_name, attribute_value_count, node_name, db_path);

/// Read the `idx` attribute value of `raw`
///
/// # Safety
///
/// Must be called with a valid event for which `idx` is in range `0..raw.attribute_value_count`
unsafe fn read_nth_attribute_value(raw: &es_event_od_attribute_set_t, idx: usize) -> es_string_token_t {
    std::ptr::read(raw.attribute_value_array.add(idx))
}

make_event_data_iterator!(
    EventOdAttributeSet;
    /// Iterator over the attribute values of an [`EventOdAttributeSet`]
    AttributeValues with attribute_value_count (usize);
    &'raw OsStr;
    read_nth_attribute_value,
    super::as_os_str,
);
