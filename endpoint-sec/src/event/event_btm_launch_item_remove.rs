//! [`EventBtmLaunchItemRemove`]

use endpoint_sec_sys::es_event_btm_launch_item_remove_t;

use crate::{AuditToken, BtmLaunchItem, Process};

/// A launch item being removed from background task management.
#[doc(alias = "es_event_btm_launch_item_add_t")]
pub struct EventBtmLaunchItemRemove<'a> {
    /// Raw event
    pub(crate) raw: &'a es_event_btm_launch_item_remove_t,
    /// Message version
    pub(crate) version: u32,
}

impl<'a> EventBtmLaunchItemRemove<'a> {
    /// Optional. Process that instigated the BTM operation (XPC caller that asked for the item to
    /// be removed).
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

    /// Optional. App process that removed the item.
    #[inline(always)]
    pub fn app(&self) -> Option<Process<'a>> {
        // Safety: 'a tied to self, object obtained through ES
        let process = unsafe { self.raw.app()? };
        Some(Process::new(process, self.version))
    }

    /// Audit token of the app process that removed the item.
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
}

// Safety: safe to send across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Send for EventBtmLaunchItemRemove<'_> {}
// Safety: safe to share across threads: does not contain any interior mutability nor depend on current thread state
unsafe impl Sync for EventBtmLaunchItemRemove<'_> {}

impl_debug_eq_hash_with_functions!(EventBtmLaunchItemRemove<'a>; instigator, instigator_token, app, app_token, item);
