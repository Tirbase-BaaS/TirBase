// SPDX-License-Identifier: AGPL-3.0-only

//! EPCIS 2.0 vocabulary export (CC-15).
//!
//! Captured EPCIS events cite `bizLocation` and `readPoint` as SGLNs. A capture
//! system needs the master data that defines those ids, in the form EPCIS 2.0
//! describes it: a vocabulary document with a `vocabularyType` and a
//! `vocabularyElementList`.
//!
//! Only records that carry a GS1 identifier can be expressed: a site becomes
//! `urn:epc:id:sgln:<gln>.0`, a location `urn:epc:id:sgln:<site gln>.<ext>` where
//! `<ext>` is the location's SGLN extension. Records without one are counted in
//! `skipped_without_gs1` rather than given an invented identifier.

use serde::{Deserialize, Serialize};

use crate::master_data::{MasterAttributes, MasterVersion};

/// Context document published by GS1 for EPCIS 2.0.
pub const EPCIS_CONTEXT: &str = "https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld";

/// Which EPCIS vocabulary to emit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EpcisVocabulary {
    /// `BizLocation`: the sites, locations and zones an event can name.
    BizLocation,
    /// `ReadPoint`: the points where an event can be observed.
    ReadPoint,
}

impl EpcisVocabulary {
    /// The `vocabularyType` string EPCIS expects.
    pub fn as_str(self) -> &'static str {
        match self {
            EpcisVocabulary::BizLocation => "BizLocation",
            EpcisVocabulary::ReadPoint => "ReadPoint",
        }
    }
}

/// One vocabulary element.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpcisVocabularyElement {
    /// `@id`, the SGLN URN.
    #[serde(rename = "@id")]
    pub id: String,
    /// `cbv:name`, the human-readable label.
    #[serde(rename = "cbv:name")]
    pub name: String,
    /// `tirbase:masterDataId`, the internal identifier.
    #[serde(rename = "tirbase:masterDataId")]
    pub master_data_id: String,
    /// `tirbase:masterDataVersion`, the version in force.
    #[serde(rename = "tirbase:masterDataVersion")]
    pub master_data_version: u32,
    /// `tirbase:status`, the lifecycle status.
    #[serde(rename = "tirbase:status")]
    pub status: String,
    /// `tirbase:siteId`, the owning site.
    #[serde(rename = "tirbase:siteId", skip_serializing_if = "Option::is_none")]
    pub site_id: Option<String>,
}

/// An EPCIS 2.0 vocabulary document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpcisVocabularyDocument {
    /// `@context`.
    #[serde(rename = "@context")]
    pub context: Vec<serde_json::Value>,
    /// Always `Vocabulary`.
    #[serde(rename = "type")]
    pub document_type: String,
    /// `BizLocation` or `ReadPoint`.
    #[serde(rename = "vocabularyType")]
    pub vocabulary_type: String,
    /// When the document was produced.
    #[serde(rename = "creationDate")]
    pub creation_date: i64,
    /// The elements.
    #[serde(rename = "vocabularyElementList")]
    pub vocabulary_element_list: Vec<EpcisVocabularyElement>,
    /// Records that carry no GS1 identifier and so could not be expressed.
    #[serde(rename = "tirbase:skippedWithoutGs1")]
    pub skipped_without_gs1: usize,
}

impl EpcisVocabularyDocument {
    /// Canonical JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Build the document from the versions in force.
pub fn build(
    vocabulary: EpcisVocabulary,
    versions: &[MasterVersion],
    creation_est: i64,
) -> EpcisVocabularyDocument {
    let mut elements = Vec::new();
    let mut skipped = 0usize;
    for version in versions {
        let Some(gs1) = version.attributes.gs1_id() else {
            skipped += 1;
            continue;
        };
        // Zones have no SGLN of their own; they are addressable through the
        // location that contains them, which the caller exports separately.
        if matches!(version.attributes, MasterAttributes::StorageZone(_)) {
            skipped += 1;
            continue;
        }
        let Some(urn) = sgln_urn(&version.attributes, gs1) else {
            skipped += 1;
            continue;
        };
        elements.push(EpcisVocabularyElement {
            id: urn,
            name: version.attributes.name().to_string(),
            master_data_id: version.id.clone(),
            master_data_version: version.version,
            status: version.status.as_str().to_string(),
            site_id: version.site_id.clone(),
        });
    }
    EpcisVocabularyDocument {
        context: vec![
            serde_json::Value::String(EPCIS_CONTEXT.to_string()),
            serde_json::json!({ "tirbase": "https://tirbase.example/vocab/" }),
        ],
        document_type: "Vocabulary".to_string(),
        vocabulary_type: vocabulary.as_str().to_string(),
        creation_date: creation_est,
        vocabulary_element_list: elements,
        skipped_without_gs1: skipped,
    }
}

/// SGLN URN for a site (extension 0) or a location (its SGLN extension).
fn sgln_urn(attributes: &MasterAttributes, gs1: &str) -> Option<String> {
    match attributes {
        MasterAttributes::Site(_) => Some(format!("urn:epc:id:sgln:{gs1}.0")),
        MasterAttributes::Location(_) => Some(format!("urn:epc:id:sgln:{gs1}")),
        MasterAttributes::Party(_) => Some(format!("urn:epc:id:sgln:{gs1}.0")),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::master_data::{
        LifecycleStatus, LocationAttributes, LocationKind, MasterVersion, SiteAttributes,
        StorageZoneAttributes,
    };
    use tirbase_types::{FixedPointValue, UNIT_DEG_C};

    fn version(id: &str, attributes: MasterAttributes) -> MasterVersion {
        MasterVersion {
            kind: attributes.kind(),
            id: id.to_string(),
            version: 1,
            effective_from_est: 0,
            effective_to_est: None,
            status: LifecycleStatus::Active,
            parent_id: None,
            site_id: Some("site-1".to_string()),
            attributes,
            digest: "00".to_string(),
            actor_did: "did:key:test".to_string(),
            created_est: 0,
        }
    }

    #[test]
    fn sites_and_locations_become_sgln_elements_and_zones_are_counted() {
        let site = version(
            "site-1",
            MasterAttributes::Site(SiteAttributes {
                name: "Dock 1".to_string(),
                gln: "4006381333931".to_string(),
                country: "DE".to_string(),
                operator_party_id: None,
            }),
        );
        let location = version(
            "loc-1",
            MasterAttributes::Location(LocationAttributes {
                site_id: "site-1".to_string(),
                parent_location_id: None,
                name: "Cold room".to_string(),
                kind: LocationKind::ColdRoom,
                gln: Some("4006381333933".to_string()),
            }),
        );
        let zone = version(
            "zone-1",
            MasterAttributes::StorageZone(StorageZoneAttributes {
                site_id: "site-1".to_string(),
                location_id: "loc-1".to_string(),
                name: "2-8C".to_string(),
                storage_class: "2-8C".to_string(),
                min_temp_c: FixedPointValue::new(20, -1, UNIT_DEG_C),
                max_temp_c: FixedPointValue::new(80, -1, UNIT_DEG_C),
            }),
        );
        let document = build(
            EpcisVocabulary::BizLocation,
            &[site, location, zone],
            1_770_000_000,
        );
        assert_eq!(document.document_type, "Vocabulary");
        assert_eq!(document.vocabulary_type, "BizLocation");
        assert_eq!(document.vocabulary_element_list.len(), 2);
        assert_eq!(
            document.vocabulary_element_list[0].id,
            "urn:epc:id:sgln:4006381333931.0"
        );
        assert_eq!(
            document.vocabulary_element_list[1].id,
            "urn:epc:id:sgln:4006381333933"
        );
        assert_eq!(document.skipped_without_gs1, 1);
    }
}
