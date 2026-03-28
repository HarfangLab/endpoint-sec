//! [`EventBtmLaunchItemAdd`]

use std::ffi::OsStr;

use endpoint_sec_sys::{es_btm_item_type_t, es_btm_launch_item_t, es_event_btm_launch_item_add_t, uid_t};

use crate::{AuditToken, Process};

/// A launch item being made known to background task management.
#[doc(alias = "es_event_btm_launch_item_add_t")]
pub struct EventBtmLaunchItemAdd<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_btm_launch_item_add_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventBtmLaunchItemAdd<'a> {
    /// Optional. Process that instigated the BTM operation (XPC caller that asked for the item to
    /// be added).
    #[inline(always)]
    pub fn instigator(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.instigator()? };
        Some(Process::new(process, self.version))
    }

    /// Audit token of the process that instigated this event.
    pub fn instigator_token(&self) -> Option<AuditToken> {
        #[cfg(feature = "macos_15_0_0")]
        if self.version >= 8 {
            // Safety: 'a tied to self, object obtained through ES
            let token = unsafe { self.raw.instigator_token() };
            return token.map(|v| AuditToken(*v));
        }

        // On older version, grab it from the instigator object.
        self.instigator().map(|v| v.audit_token())
    }

    /// Optional. App process that registered the item.
    #[inline(always)]
    pub fn app(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.app()? };
        Some(Process::new(process, self.version))
    }

    /// Audit token of the process that instigated this event.
    pub fn app_token(&self) -> Option<AuditToken> {
        #[cfg(feature = "macos_15_0_0")]
        if self.version >= 8 {
            // Safety: 'a tied to self, object obtained through ES
            let token = unsafe { self.raw.app_token() };
            return token.map(|v| AuditToken(*v));
        }

        // On older version, grab it from the instigator object.
        self.app().map(|v| v.audit_token())
    }

    /// BTM launch item.
    #[inline(always)]
    pub fn item(&self) -> BtmLaunchItem<'a> {
        // Safety: 'a tied to self, object obtained through ES
        BtmLaunchItem::new(unsafe { self.raw.item() })
    }

    /// Optional. If available and applicable, the POSIX executable path from the launchd plist. If
    /// the path is relative, it is relative to `item.app_url`.
    #[inline(always)]
    pub fn executable_path(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.executable_path.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventBtmLaunchItemAdd<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventBtmLaunchItemAdd<'_> {}

impl_debug_eq_hash_with_functions!(
    EventBtmLaunchItemAdd<'a>;
    instigator, instigator_token, app, app_token, item, executable_path,
);

/// A BTM launch item
#[doc(alias = "es_btm_launch_item_t")]
pub struct BtmLaunchItem<'a> {
    /// Raw data
    pub(crate) raw: &'a es_btm_launch_item_t,
}

impl<'a> BtmLaunchItem<'a> {
    /// New launch item
    #[inline(always)]
    pub(crate) fn new(raw: &'a es_btm_launch_item_t) -> Self {
        Self { raw }
    }

    /// Type of launch item.
    #[inline(always)]
    pub fn item_type(&self) -> es_btm_item_type_t {
        self.raw.item_type
    }

    /// True only if item is a legacy plist.
    #[inline(always)]
    pub fn legacy(&self) -> bool {
        self.raw.legacy
    }

    /// True only if item is managed by MDM.
    #[inline(always)]
    pub fn managed(&self) -> bool {
        self.raw.managed
    }

    /// User ID for the item (may be user `nobody` (`-2`)).
    #[inline(always)]
    pub fn uid(&self) -> uid_t {
        self.raw.uid
    }

    /// URL for item.
    ///
    /// If a file URL describing a relative path, it is relative to `app_url`.
    #[inline(always)]
    pub fn item_url(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.item_url.as_os_str() }
    }

    /// Optional. URL for app the item is attributed to.
    #[inline(always)]
    pub fn app_url(&self) -> &'a OsStr {
        // Safety: 'a tied to self, object obtained through ES
        unsafe { self.raw.app_url.as_os_str() }
    }
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for BtmLaunchItem<'_> {}

impl_debug_eq_hash_with_functions!(
    BtmLaunchItem<'a>;
    item_type, legacy, managed, uid, item_url, app_url,
);
