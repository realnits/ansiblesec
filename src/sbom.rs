use std::path::Path;
use serde_yaml::Value;
use walkdir::WalkDir;

use crate::errors::Result;

pub struct SbomGenerator {
    include_cve: bool,
}

#[derive(Debug, serde::Serialize)]
struct Component {
    name: String,
    version: String,
    #[serde(rename = "type")]
    component_type: String,
    description: Option<String>,
    cves: Vec<String>,
}

impl SbomGenerator {
    pub fn new(include_cve: bool) -> Self {
        Self { include_cve }
    }
    
    pub fn generate(&self, path: &Path, format: &str) -> Result<String> {
        let components = self.extract_components(path)?;
        
        match format {
            "cyclonedx" => self.generate_cyclonedx(components),
            "spdx" => self.generate_spdx(components),
            _ => Err(crate::errors::AnsibleSecError::ConfigError(
                format!("Unknown SBOM format: {}", format)
            )),
        }
    }
    
    fn extract_components(&self, path: &Path) -> Result<Vec<Component>> {
        let mut components = Vec::new();
        
        // Find all requirements.yml files (for collections and roles)
        for entry in WalkDir::new(path)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_name() == "requirements.yml" || entry.file_name() == "requirements.yaml" {
                let content = std::fs::read_to_string(entry.path())?;
                if let Ok(yaml) = serde_yaml::from_str::<Value>(&content) {
                    components.extend(self.parse_requirements(&yaml)?);
                }
            }
            
            // Also check for galaxy.yml (collection metadata)
            if entry.file_name() == "galaxy.yml" {
                let content = std::fs::read_to_string(entry.path())?;
                if let Ok(yaml) = serde_yaml::from_str::<Value>(&content) {
                    if let Some(component) = self.parse_galaxy_metadata(&yaml)? {
                        components.push(component);
                    }
                }
            }
        }
        
        // Fetch CVEs if enabled
        if self.include_cve {
            for component in &mut components {
                component.cves = self.fetch_cves(&component.name, &component.version).unwrap_or_default();
            }
        }
        
        Ok(components)
    }
    
    fn parse_requirements(&self, yaml: &Value) -> Result<Vec<Component>> {
        let mut components = Vec::new();
        
        // Parse roles
        if let Some(roles) = yaml.get("roles").and_then(|r| r.as_sequence()) {
            for role in roles {
                if let Some(obj) = role.as_mapping() {
                    let name = obj.get("name")
                        .or_else(|| obj.get("src"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let version = obj.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("latest");
                    
                    components.push(Component {
                        name: name.to_string(),
                        version: version.to_string(),
                        component_type: "ansible-role".to_string(),
                        description: None,
                        cves: vec![],
                    });
                }
            }
        }
        
        // Parse collections
        if let Some(collections) = yaml.get("collections").and_then(|c| c.as_sequence()) {
            for collection in collections {
                if let Some(obj) = collection.as_mapping() {
                    let name = obj.get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let version = obj.get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("latest");
                    
                    components.push(Component {
                        name: name.to_string(),
                        version: version.to_string(),
                        component_type: "ansible-collection".to_string(),
                        description: None,
                        cves: vec![],
                    });
                }
            }
        }
        
        Ok(components)
    }
    
    fn parse_galaxy_metadata(&self, yaml: &Value) -> Result<Option<Component>> {
        if let Some(name) = yaml.get("name").and_then(|v| v.as_str()) {
            let version = yaml.get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let description = yaml.get("description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            
            Ok(Some(Component {
                name: name.to_string(),
                version: version.to_string(),
                component_type: "ansible-collection".to_string(),
                description,
                cves: vec![],
            }))
        } else {
            Ok(None)
        }
    }
    
    fn fetch_cves(&self, name: &str, version: &str) -> Result<Vec<String>> {
        // This is a simplified CVE lookup
        // In production, you'd query NVD API or similar
        log::info!("Fetching CVEs for {} {}", name, version);
        
        // Placeholder - would make actual API calls
        Ok(vec![])
    }
    
    fn generate_cyclonedx(&self, components: Vec<Component>) -> Result<String> {
        let cyclonedx_components: Vec<serde_json::Value> = components
            .iter()
            .map(|c| {
                serde_json::json!({
                    "type": "library",
                    "name": c.name,
                    "version": c.version,
                    "purl": format!("pkg:ansible/{}", c.name),
                    "description": c.description,
                })
            })
            .collect();
        
        let bom = serde_json::json!({
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "version": 1,
            "metadata": {
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "tools": [{
                    "name": "ansiblesec",
                    "version": env!("CARGO_PKG_VERSION")
                }]
            },
            "components": cyclonedx_components
        });
        
        Ok(serde_json::to_string_pretty(&bom)?)
    }
    
    fn generate_spdx(&self, components: Vec<Component>) -> Result<String> {
        let packages: Vec<serde_json::Value> = components
            .iter()
            .enumerate()
            .map(|(idx, c)| {
                serde_json::json!({
                    "SPDXID": format!("SPDXRef-Package-{}", idx),
                    "name": c.name,
                    "versionInfo": c.version,
                    "downloadLocation": "NOASSERTION",
                    "filesAnalyzed": false,
                    "copyrightText": "NOASSERTION"
                })
            })
            .collect();
        
        let spdx = serde_json::json!({
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "Ansible Security SBOM",
            "documentNamespace": format!("https://ansiblesec.example.com/sbom/{}", uuid::Uuid::new_v4()),
            "creationInfo": {
                "created": chrono::Utc::now().to_rfc3339(),
                "creators": [
                    format!("Tool: ansiblesec-{}", env!("CARGO_PKG_VERSION"))
                ]
            },
            "packages": packages
        });
        
        Ok(serde_json::to_string_pretty(&spdx)?)
    }
}
