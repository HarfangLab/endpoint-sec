//! [`EventOdGroupAdd`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_event_od_group_add_t, es_od_member_id_t, es_od_member_id_t_anon0, es_od_member_type_t};

use crate::Process;

/// Notification that a member was added to a group.
///
/// This event does not indicate that a member was actually added. For example when adding a user
/// to a group they are already a member of.
#[doc(alias = "es_event_od_group_add_t")]
pub struct EventOdGroupAdd<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_group_add_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdGroupAdd<'a> {
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

    /// The group to which the member was added.
    #[inline(always)]
    pub fn group_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.group_name.as_os_str() }
    }

    /// The identity of the member added.
    #[inline(always)]
    pub fn member(&self) -> OdMemberId<'a> {
        OdMemberId {
            // Safety: 'a tied to self, object obtained through ES
            raw: unsafe { self.raw.member.as_ref() },
        }
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
unsafe impl Send for EventOdGroupAdd<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventOdGroupAdd<'_> {}

impl_debug_eq_hash_with_functions!(EventOdGroupAdd<'a> with version; instigator, error_code, group_name, member, node_name, db_path);

/// The identity of a group member
#[doc(alias = "es_od_member_id_t")]
pub struct OdMemberId<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_od_member_id_t,
}

impl<'a> OdMemberId<'a> {
    /// Indicates the type of the member, and how it is identified.
    #[inline(always)]
    pub fn member_type(&self) -> es_od_member_type_t {
        self.raw.member_type
    }

    /// The member identity, as its raw value.
    #[inline(always)]
    pub fn raw_member_value(&self) -> &'a es_od_member_id_t_anon0 {
        &self.raw.member_value
    }

    /// The member identity.
    #[inline(always)]
    pub fn member_value(&self) -> Option<OdMemberIdValue<'a>> {
        // Safety in general: we check against the 'member_type' before accessing the union
        let res = match self.member_type() {
            es_od_member_type_t::ES_OD_MEMBER_TYPE_USER_UUID => {
                // Safety: 'a tied to self, object obtained through ES
                OdMemberIdValue::UserUuid(unsafe { self.raw.member_value.uuid })
            },
            es_od_member_type_t::ES_OD_MEMBER_TYPE_GROUP_UUID => {
                // Safety: 'a tied to self, object obtained through ES
                OdMemberIdValue::GroupUuid(unsafe { self.raw.member_value.uuid })
            },
            es_od_member_type_t::ES_OD_MEMBER_TYPE_USER_NAME => {
                // Safety: 'a tied to self, object obtained through ES
                OdMemberIdValue::UserName(unsafe { self.raw.member_value.name.as_os_str() })
            },
            _ => return None,
        };

        Some(res)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for OdMemberId<'_> {}

impl_debug_eq_hash_with_functions!(OdMemberId<'a>; member_type, member_value);

/// A member identity.
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum OdMemberIdValue<'a> {
    /// Group member is a user, designated by name
    UserName(&'a OsStr),
    /// Group member is a user, designated by UUID
    UserUuid(libc::uuid_t),
    /// Group member is another group, designated by UUID
    GroupUuid(libc::uuid_t),
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for OdMemberIdValue<'_> {}
