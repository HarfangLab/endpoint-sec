//! [`EventAuthentication`]

use std::ffi::OsStr;

use endpoint_sec_sys::{
    es_authentication_type_t, es_auto_unlock_type_t, es_event_authentication_auto_unlock_t,
    es_event_authentication_od_t, es_event_authentication_t, es_event_authentication_t_anon0,
    es_event_authentication_token_t, es_event_authentication_touchid_t, es_touchid_mode_t, uid_t,
};

use crate::Process;

/// An authentication was performed.
#[doc(alias = "es_event_authentication_t")]
pub struct EventAuthentication<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_authentication_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventAuthentication<'a> {
    /// True iff authentication was successful.
    #[inline(always)]
    pub fn success(&self) -> bool {
        self.raw.success
    }

    /// The type of authentication.
    #[inline(always)]
    pub fn type_(&self) -> es_authentication_type_t {
        self.raw.type_
    }

    /// Type-specific data describing the authentication.
    #[inline(always)]
    pub fn raw_data(&self) -> &'a es_event_authentication_t_anon0 {
        &self.raw.data
    }

    /// Details about event
    #[inline(always)]
    pub fn data(&self) -> Option<AuthenticationData<'a>> {
        let res = match self.type_() {
            es_authentication_type_t::ES_AUTHENTICATION_TYPE_OD => AuthenticationData::Od(EventAuthenticationOd {
                // Safety: access to union is gated on relevant enum
                raw: unsafe { self.raw_data().od.as_opt()? },
                version: self.version,
            }),
            es_authentication_type_t::ES_AUTHENTICATION_TYPE_TOUCHID => {
                AuthenticationData::TouchId(EventAuthenticationTouchId {
                    // Safety: access to union is gated on relevant enum
                    raw: unsafe { self.raw_data().touchid.as_opt()? },
                    version: self.version,
                    success: self.success(),
                })
            },
            es_authentication_type_t::ES_AUTHENTICATION_TYPE_TOKEN => {
                AuthenticationData::Token(EventAuthenticationToken {
                    // Safety: access to union is gated on relevant enum
                    raw: unsafe { self.raw_data().token.as_opt()? },
                    version: self.version,
                })
            },
            es_authentication_type_t::ES_AUTHENTICATION_TYPE_AUTO_UNLOCK => {
                AuthenticationData::AutoUnlock(EventAuthenticationAutoUnlock {
                    // Safety: access to union is gated on relevant enum
                    raw: unsafe { self.raw_data().auto_unlock.as_opt()? },
                })
            },
            _ => return None,
        };
        Some(res)
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthentication<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventAuthentication<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthentication<'a>; success, type_, data);

/// See [`es_event_authentication_t_anon0`]
#[doc(alias = "es_event_authentication_t_anon0")]
#[doc(alias = "es_authentication_type_t")]
#[derive(Debug, PartialEq, Eq, Hash)]
pub enum AuthenticationData<'a> {
    /// Wrapped [`es_event_authentication_t_anon_0.od`]
    Od(EventAuthenticationOd<'a>),
    /// Wrapped [`es_event_authentication_t_anon_0.touchid`]
    TouchId(EventAuthenticationTouchId<'a>),
    /// Wrapped [`es_event_authentication_t_anon_0.token`]
    Token(EventAuthenticationToken<'a>),
    /// Wrapped [`es_event_authentication_t_anon_0.auto_unlock`]
    AutoUnlock(EventAuthenticationAutoUnlock<'a>),
}

/// OpenDirectory authentication data
#[doc(alias = "es_event_authentication_od_t")]
pub struct EventAuthenticationOd<'a> {
    /// Raw event
    raw: &'a es_event_authentication_od_t,
    /// Message version
    version: u32,
}

impl<'a> EventAuthenticationOd<'a> {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.instigator.as_ref() },
            self.version,
        )
    }

    /// OD record type against which OD is authenticating. Typically `Users`, but other record types
    /// can auth too.
    #[inline(always)]
    pub fn record_type(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.record_type.as_os_str() }
    }

    /// OD record name against which OD is authenticating. For record type `Users`, this is the
    /// username.
    #[inline(always)]
    pub fn record_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.record_name.as_os_str() }
    }

    /// OD node against which OD is authenticating. Typically one of `/Local/Default`, `/LDAPv3/
    /// <server>` or `/Active Directory/<domain>`.
    #[inline(always)]
    pub fn node_name(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.node_name.as_os_str() }
    }

    /// Optional. If node_name is "/Local/Default", this is the path of the database against which
    /// OD is authenticating.
    #[inline(always)]
    pub fn db_path(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.db_path.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthenticationOd<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthenticationOd<'a>; instigator, record_name, node_name, db_path);

/// TouchID authentication data
#[doc(alias = "es_event_authentication_touchid_t")]
pub struct EventAuthenticationTouchId<'a> {
    /// Raw event
    raw: &'a es_event_authentication_touchid_t,
    /// Message version
    version: u32,
    /// Overall identification success
    success: bool,
}

impl<'a> EventAuthenticationTouchId<'a> {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.instigator.as_ref() },
            self.version,
        )
    }

    /// TouchID authentication type
    #[inline(always)]
    pub fn touchid_mode(&self) -> es_touchid_mode_t {
        self.raw.touchid_mode
    }

    /// Describes whether or not the uid of the user authenticated is available
    #[inline(always)]
    pub fn has_uid(&self) -> bool {
        self.raw.has_uid
    }

    /// UID of user that was authenticated.
    #[inline(always)]
    pub fn uid(&self) -> Option<uid_t> {
        match (self.has_uid(), self.success, self.touchid_mode()) {
            // Safety: access is gated on documented conditions
            (true, true, es_touchid_mode_t::ES_TOUCHID_MODE_VERIFICATION) => unsafe { Some(self.raw.anon0.uid) },
            _ => None,
        }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthenticationTouchId<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthenticationTouchId<'a>; instigator, touchid_mode, has_uid, uid);

/// Token authentication data
#[doc(alias = "es_event_authentication_token_t")]
pub struct EventAuthenticationToken<'a> {
    /// Raw event
    raw: &'a es_event_authentication_token_t,
    /// Message version
    version: u32,
}

impl<'a> EventAuthenticationToken<'a> {
    /// Process that instigated the authentication (XPC caller that asked for authentication).
    #[inline(always)]
    pub fn instigator(&self) -> Process<'a> {
        Process::new(
            // Safety: 'a tied to self, object obtained through ES
            unsafe { self.raw.instigator.as_ref() },
            self.version,
        )
    }

    /// Hash of the public key which CryptoTokenKit is authenticating.
    #[inline(always)]
    pub fn pubkey_hash(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.pubkey_hash.as_os_str() }
    }

    /// Token identifier of the event which CryptoTokenKit is authenticating.
    #[inline(always)]
    pub fn token_id(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.token_id.as_os_str() }
    }

    /// Optional. This will be available if token is used for GSS PKINIT authentication for
    /// obtaining a kerberos TGT. `NULL` in all other cases.
    #[inline(always)]
    pub fn kerberos_principal(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.kerberos_principal.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthenticationToken<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthenticationToken<'a>; instigator, pubkey_hash, token_id, kerberos_principal);

/// Auto unlock authentication data
#[doc(alias = "es_event_authentication_auto_unlock_t")]
pub struct EventAuthenticationAutoUnlock<'a> {
    /// Raw event
    raw: &'a es_event_authentication_auto_unlock_t,
}

impl<'a> EventAuthenticationAutoUnlock<'a> {
    /// Username for which the authentication was attempted.
    #[inline(always)]
    pub fn username(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.username.as_os_str() }
    }

    /// Purpose of the authentication.
    #[inline(always)]
    pub fn type_(&self) -> es_auto_unlock_type_t {
        self.raw.type_
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventAuthenticationAutoUnlock<'_> {}

impl_debug_eq_hash_with_functions!(EventAuthenticationAutoUnlock<'a>; username, type_);
