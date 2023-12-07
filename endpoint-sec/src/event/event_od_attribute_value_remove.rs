//! [`EventOdAttributeValueRemove`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_od_attribute_value_remove_t, es_od_record_type_t};

use crate::Process;

/// Notification that an attribute value was removed to a record.
///
/// Attributes conceptually have the type `Map String (Set String)`.
/// Each OD record has a Map of attribute name to Set of attribute value.
/// When an attribute value is removed, it is inserted into the set of values for that name.
///
/// Removing a value that was never added is a no-op.
#[doc(alias = "es_event_od_attribute_value_remove_t")]
pub struct EventOdAttributeValueRemove<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_attribute_value_remove_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdAttributeValueRemove<'a> {
    /// Process that instigated operation (XPC caller).
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        // Safety: 'a tied to self, object obtained through ES
        Process::new(unsafe { self.raw.instigator.as_ref() }, self.version)
    }

    /// Result code for the operation.
    #[inline(always)]
    pub fn error_code(&self) -> i32 {
        self.raw.error_code
    }
    /// The type of the record to which the attribute value was removed.
    #[inline(always)]
    pub fn record_type(&self) -> es_od_record_type_t {
        self.raw.record_type
    }

    /// The name of the record to which the attribute value was removed.
    #[inline(always)]
    pub fn record_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.record_name.as_os_str() }
    }

    /// The name of the attribute to which the value was removed.
    #[inline(always)]
    pub fn attribute_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.attribute_name.as_os_str() }
    }

    /// The value that was removed.
    #[inline(always)]
    pub fn attribute_value(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.attribute_value.as_os_str() }
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
unsafe impl Send for EventOdAttributeValueRemove<'_> {}

impl_debug_eq_hash_with_functions!(EventOdAttributeValueRemove<'a> with version; instigator, error_code, record_type, record_name, attribute_name, attribute_value, node_name, db_path);
