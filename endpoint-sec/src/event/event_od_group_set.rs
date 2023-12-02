//! [`EventOdGroupSet`]

use std::ffi::OsStr;

use endpoint_sec_sys::{
    es_event_od_group_set_t, es_od_member_id_array_t, es_od_member_id_array_t_anon0, es_od_member_type_t,
    es_string_token_t,
};

use crate::Process;

/// Notification that a group had it's members initialised or replaced.
#[doc(alias = "es_event_od_group_set_t")]
pub struct EventOdGroupSet<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_event_od_group_set_t,
    /// The version of the message.
    pub(crate) version: u32,
}

impl<'a> EventOdGroupSet<'a> {
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

    /// The group to which members were set.
    #[inline(always)]
    pub fn group_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.group_name.as_os_str() }
    }

    /// Array of new members.
    #[inline(always)]
    pub fn members(&self) -> OdMemberIdArray<'a> {
        OdMemberIdArray {
            // Safety: 'a tied to self, object obtained through ES
            raw: unsafe { self.raw.members.as_ref() },
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
unsafe impl Send for EventOdGroupSet<'_> {}

impl_debug_eq_hash_with_functions!(EventOdGroupSet<'a> with version; instigator, error_code, group_name, members, node_name, db_path);

/// An array of group member identities.
#[doc(alias = "es_od_member_id_array_t")]
pub struct OdMemberIdArray<'a> {
    /// The raw reference.
    pub(crate) raw: &'a es_od_member_id_array_t,
}

impl<'a> OdMemberIdArray<'a> {
    /// Indicates the type of the members, and how they are identified.
    #[inline(always)]
    pub fn member_type(&self) -> es_od_member_type_t {
        self.raw.member_type
    }

    /// The number of elements.
    #[inline(always)]
    pub fn member_count(&self) -> usize {
        self.raw.member_count
    }

    /// The members identity, as its raw value.
    #[inline(always)]
    pub fn raw_member_array(&self) -> &'a es_od_member_id_array_t_anon0 {
        &self.raw.member_array
    }

    /// Iterator over the relevant union value based on the member type.
    #[inline(always)]
    pub fn members<'arr>(&'arr self) -> Option<OdMemberIdArrayIters<'arr, 'a>> {
        let res = match self.member_type() {
            es_od_member_type_t::ES_OD_MEMBER_TYPE_USER_NAME => {
                OdMemberIdArrayIters::UserName(OdMemberIdArrayNames::new(self))
            },
            es_od_member_type_t::ES_OD_MEMBER_TYPE_USER_UUID => {
                OdMemberIdArrayIters::UserUuid(OdMemberIdArrayUuids::new(self))
            },
            es_od_member_type_t::ES_OD_MEMBER_TYPE_GROUP_UUID => {
                OdMemberIdArrayIters::GroupUuid(OdMemberIdArrayUuids::new(self))
            },
            _ => return None,
        };
        Some(res)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for OdMemberIdArray<'_> {}

impl_debug_eq_hash_with_functions!(OdMemberIdArray<'a>; member_type, member_count);

/// One of the possible iterator for [`OdMemberIdArray`]
pub enum OdMemberIdArrayIters<'arr, 'raw> {
    /// Users, designated by name
    UserName(OdMemberIdArrayNames<'arr, 'raw>),
    /// Users, designated by UUID
    UserUuid(OdMemberIdArrayUuids<'arr, 'raw>),
    /// Groups, designated by UUID
    GroupUuid(OdMemberIdArrayUuids<'arr, 'raw>),
}

/// Read the `idx` name of `raw`
///
/// # Safety
///
/// Must be called with a valid member array for which `idx` is in range `0..raw.member_count` and the
/// member type is correct.
unsafe fn read_nth_name(raw: &es_od_member_id_array_t, idx: usize) -> es_string_token_t {
    std::ptr::read(raw.member_array.names.as_ptr().add(idx))
}

make_event_data_iterator!(
    OdMemberIdArray;
    /// Iterator over the names in an [`OdMemberIdArray`]
    OdMemberIdArrayNames with member_count (usize);
    &'raw OsStr;
    read_nth_name,
    super::as_os_str,
);

/// Read the `idx` uuid of `raw`
///
/// # Safety
///
/// Must be called with a valid member array for which `idx` is in range `0..raw.member_count` and the
/// member type is correct.
unsafe fn read_nth_uuid(raw: &es_od_member_id_array_t, idx: usize) -> libc::uuid_t {
    std::ptr::read(raw.member_array.uuids.as_ptr().add(idx))
}

make_event_data_iterator!(
    OdMemberIdArray;
    /// Iterator over the uuids in an [`OdMemberIdArray`]
    OdMemberIdArrayUuids with member_count (usize);
    libc::uuid_t;
    read_nth_uuid,
    std::convert::identity,
);
