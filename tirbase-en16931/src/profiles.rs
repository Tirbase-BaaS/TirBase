// SPDX-License-Identifier: Apache-2.0

//! Country-profile extension points.
//!
//! The core crate implements the EN 16931 core invoice and nothing else: it never
//! emits a national fiscal code, a verification URL, a qualified signature or a
//! national schema identifier, and it makes no claim about national requirements.
//! A country profile is a **closed commercial module** that links this crate and
//! implements [`CountryProfile`]. That trait is the only place country logic can
//! live, and it has four hooks:
//!
//! - [`CountryProfile::customization_id`] — the specification identifier written
//!   into BT-24 (UBL `cbc:CustomizationID`, CII
//!   `ram:GuidelineSpecifiedDocumentContextParameter/ram:ID`);
//! - [`CountryProfile::profile_id`] — the business process identifier written into
//!   BT-23 (UBL `cbc:ProfileID`);
//! - [`CountryProfile::extension`] — extra content for the standard UBL
//!   `ext:UBLExtensions` container, with the namespaces it needs;
//! - [`CountryProfile::validate`] and [`CountryProfile::wrap`] — national rules,
//!   and the last chance to reshape a finished core document.
//!
//! A profile is registered by identifier so a host can select it by name:
//!
//! ```
//! use tirbase_en16931::profiles::{self, CountryProfile};
//! use tirbase_en16931::model::{Invoice, ValidationIssue};
//! use tirbase_en16931::validate::Syntax;
//!
//! struct Example;
//!
//! impl CountryProfile for Example {
//!     fn id(&self) -> &'static str {
//!         "example-national"
//!     }
//!     fn description(&self) -> &'static str {
//!         "A closed profile that is not part of this crate"
//!     }
//!     fn validate(&self, _invoice: &Invoice) -> Vec<ValidationIssue> {
//!         Vec::new()
//!     }
//!     fn wrap(&self, _syntax: Syntax, document: String) -> Result<String, String> {
//!         Ok(document)
//!     }
//! }
//!
//! static EXAMPLE: Example = Example;
//! profiles::register(&EXAMPLE).expect("registered once");
//! assert!(profiles::find("example-national").is_some());
//! ```
//!
//! The crate ships exactly one profile, [`CoreInvoice`], which adds no rule and
//! keeps the core specification identifier. Nothing in the crate knows what a
//! national requirement is.

use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use crate::model::{Invoice, ValidationIssue};
use crate::validate::Syntax;
use crate::SPECIFICATION_ID;

/// Extension content for the UBL `ext:UBLExtensions` container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Extension {
    /// Namespace prefix declared on the document root.
    pub prefix: String,
    /// Namespace the prefix is bound to.
    pub namespace: String,
    /// Local name of the extension element.
    pub name: String,
    /// Child elements as `(qualified name, text)`, in writing order.
    pub children: Vec<(String, String)>,
}

impl Extension {
    /// Build an extension element.
    pub fn new(prefix: &str, namespace: &str, name: &str) -> Self {
        Self {
            prefix: prefix.to_string(),
            namespace: namespace.to_string(),
            name: name.to_string(),
            children: Vec::new(),
        }
    }

    /// Append a child element.
    pub fn with_child(mut self, name: &str, text: &str) -> Self {
        self.children.push((name.to_string(), text.to_string()));
        self
    }
}

/// The national extension point.
///
/// A profile is a closed module: it is not part of this crate, it is registered by
/// the host, and the core keeps working without it.
pub trait CountryProfile: Send + Sync {
    /// Stable identifier used to select the profile.
    fn id(&self) -> &'static str;

    /// One-line description.
    fn description(&self) -> &'static str;

    /// Specification identifier written into BT-24. Defaults to the core id.
    fn customization_id(&self) -> &'static str {
        SPECIFICATION_ID
    }

    /// Business process identifier written into BT-23 (UBL only), when the profile
    /// needs one.
    fn profile_id(&self) -> Option<&'static str> {
        None
    }

    /// Content for the UBL extension container; ignored for CII, whose national
    /// content belongs in [`CountryProfile::wrap`].
    fn extension(&self, _invoice: &Invoice) -> Option<Extension> {
        None
    }

    /// National rules. The returned issues are reported next to the core rules.
    fn validate(&self, _invoice: &Invoice) -> Vec<ValidationIssue> {
        Vec::new()
    }

    /// Transform the finished core document.
    ///
    /// The default writes nothing. A profile that needs national elements, a
    /// national identifier or a national signature wraps the document here.
    fn wrap(&self, _syntax: Syntax, document: String) -> Result<String, String> {
        Ok(document)
    }
}

static REGISTRY: OnceLock<RwLock<BTreeMap<&'static str, &'static dyn CountryProfile>>> =
    OnceLock::new();

fn registry() -> &'static RwLock<BTreeMap<&'static str, &'static dyn CountryProfile>> {
    REGISTRY.get_or_init(|| RwLock::new(BTreeMap::new()))
}

/// The profile that ships with the crate: the EN 16931 core invoice, with no
/// national rule and no national identifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct CoreInvoice;

impl CountryProfile for CoreInvoice {
    fn id(&self) -> &'static str {
        "en16931-core"
    }

    fn description(&self) -> &'static str {
        "EN 16931 core invoice; adds no national requirement"
    }
}

/// The core profile.
pub fn core() -> &'static dyn CountryProfile {
    &CoreInvoice
}

/// Register a profile.
///
/// Returns `Err` when the identifier is already taken, so two profiles cannot
/// silently shadow each other.
pub fn register(profile: &'static dyn CountryProfile) -> Result<(), String> {
    let id = profile.id();
    if id.trim().is_empty() {
        return Err("a profile needs an identifier".to_string());
    }
    let mut registry = registry()
        .write()
        .map_err(|_| "the profile registry is poisoned".to_string())?;
    if registry.contains_key(id) {
        return Err(format!("profile {id:?} is already registered"));
    }
    registry.insert(id, profile);
    Ok(())
}

/// Look a profile up by identifier.
pub fn find(id: &str) -> Option<&'static dyn CountryProfile> {
    if id == core().id() {
        return Some(core());
    }
    registry()
        .read()
        .ok()
        .and_then(|registry| registry.get(id).copied())
}

/// Registered identifiers, sorted. The core identifier is always present.
pub fn ids() -> Vec<&'static str> {
    let mut ids = vec![core().id()];
    if let Ok(registry) = registry().read() {
        ids.extend(registry.keys().copied());
    }
    ids.sort_unstable();
    ids.dedup();
    ids
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Probe;

    impl CountryProfile for Probe {
        fn id(&self) -> &'static str {
            "probe"
        }

        fn description(&self) -> &'static str {
            "test profile"
        }

        fn profile_id(&self) -> Option<&'static str> {
            Some("urn:example:probe")
        }

        fn extension(&self, _invoice: &Invoice) -> Option<Extension> {
            Some(
                Extension::new("probe", "urn:example:probe:1", "Stamp")
                    .with_child("probe:ID", "P-1"),
            )
        }
    }

    static PROBE: Probe = Probe;

    #[test]
    fn the_core_profile_is_always_available() {
        assert!(find(core().id()).is_some());
        assert_eq!(core().customization_id(), SPECIFICATION_ID);
        assert!(ids().contains(&core().id()));
    }

    #[test]
    fn a_profile_registers_once_and_is_found_by_id() {
        register(&PROBE).expect("first registration");
        assert!(register(&PROBE).is_err());
        let profile = find("probe").expect("found");
        assert_eq!(profile.profile_id(), Some("urn:example:probe"));
        assert!(ids().contains(&"probe"));
        assert!(find("not-registered").is_none());
    }

    #[test]
    fn extension_building_is_total() {
        let extension = Extension::new("p", "urn:p", "Root")
            .with_child("p:A", "1")
            .with_child("p:B", "2");
        assert_eq!(extension.children.len(), 2);
        assert_eq!(extension.prefix, "p");
    }
}
