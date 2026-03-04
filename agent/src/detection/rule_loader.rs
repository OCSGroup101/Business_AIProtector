// Detection Rule Loader
//
// Loads TOML rule packs from disk (or bundled bytes) and compiles Lua scripts.
// Three rule types: ioc | behavioral | heuristic (Lua)

use anyhow::Result;
use mlua::{Function, Lua};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

use crate::core::event_bus::EventType;

// ─── Rule schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum MatchType {
    Ioc,
    Behavioral,
    Heuristic,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MitreMapping {
    #[serde(default)]
    pub tactics: Vec<String>,
    #[serde(default)]
    pub techniques: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Condition {
    pub field: String,
    pub operator: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ioc_type: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MatchBlock {
    #[serde(rename = "type")]
    pub match_type: MatchType,
    #[serde(default)]
    pub event_types: Vec<String>,
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// For heuristic rules: window in seconds
    #[serde(default)]
    pub window_seconds: u32,
    /// For heuristic rules: Lua script source
    #[serde(default)]
    pub lua_script: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ResponseBlock {
    pub severity: String,
    #[serde(default)]
    pub auto_contain: Vec<String>,
    #[serde(default)]
    pub notify: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DetectionRule {
    pub id: String,
    pub name: String,
    #[serde(default)]
    pub enabled: bool,
    #[serde(rename = "mitre")]
    pub mitre: Option<MitreMapping>,
    #[serde(rename = "match")]
    pub match_block: MatchBlock,
    pub response: ResponseBlock,
}

/// A pack manifest
#[derive(Debug, Deserialize)]
struct PackManifest {
    name: String,
    version: String,
    #[serde(default)]
    signature: String,
    #[serde(default)]
    rules: Vec<DetectionRule>,
}

/// A file with multiple [[rules]] entries
#[derive(Debug, Deserialize)]
struct RuleFile {
    #[serde(default)]
    rules: Vec<DetectionRule>,
}

// ─── Compiled rule ────────────────────────────────────────────────────────────

/// A rule compiled and ready for evaluation
pub struct CompiledRule {
    pub rule: DetectionRule,
    /// Pre-compiled Lua function for heuristic rules
    pub lua_fn: Option<mlua::RegistryKey>,
}

// ─── RuleLoader ───────────────────────────────────────────────────────────────

pub struct RuleLoader {
    /// rule_id → compiled rule
    pub rules: HashMap<String, CompiledRule>,
    lua: Lua,
}

impl RuleLoader {
    pub fn new() -> Result<Self> {
        Ok(Self {
            rules: HashMap::new(),
            lua: Lua::new(),
        })
    }

    /// Load all rule packs from `rules_dir/<pack_name>/`.
    pub fn load_packs(&mut self, rules_dir: &Path, pack_names: &[String]) -> Result<()> {
        let mut loaded = 0usize;
        let mut skipped = 0usize;

        for pack_name in pack_names {
            let pack_dir = rules_dir.join(pack_name);
            if !pack_dir.exists() {
                warn!(pack = %pack_name, "Rule pack directory not found — skipping");
                skipped += 1;
                continue;
            }

            match self.load_pack_dir(&pack_dir) {
                Ok(count) => {
                    info!(pack = %pack_name, rules = count, "Rule pack loaded");
                    loaded += count;
                }
                Err(e) => {
                    warn!(pack = %pack_name, error = %e, "Failed to load rule pack");
                    skipped += 1;
                }
            }
        }

        info!(loaded, skipped, "Rule loading complete");
        Ok(())
    }

    fn load_pack_dir(&mut self, dir: &Path) -> Result<usize> {
        let mut count = 0;

        // Walk all .toml files recursively
        for entry in walkdir_toml(dir) {
            let content = std::fs::read_to_string(&entry)?;
            let rule_file: RuleFile = toml::from_str(&content).map_err(|e| {
                anyhow::anyhow!("Failed to parse {}: {}", entry.display(), e)
            })?;

            for rule in rule_file.rules {
                if !rule.enabled {
                    debug!(id = %rule.id, "Rule disabled — skipping");
                    continue;
                }
                let lua_fn = self.compile_lua_if_needed(&rule)?;
                let id = rule.id.clone();
                self.rules.insert(id, CompiledRule { rule, lua_fn });
                count += 1;
            }
        }
        Ok(count)
    }

    fn compile_lua_if_needed(&self, rule: &DetectionRule) -> Result<Option<mlua::RegistryKey>> {
        match rule.match_block.match_type {
            MatchType::Heuristic if !rule.match_block.lua_script.is_empty() => {
                let chunk = self.lua.load(&rule.match_block.lua_script);
                let func: Function = chunk.eval().map_err(|e| {
                    anyhow::anyhow!("Lua compile error in rule {}: {}", rule.id, e)
                })?;
                let key = self.lua.create_registry_value(func)?;
                Ok(Some(key))
            }
            _ => Ok(None),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn walkdir_toml(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                files.extend(walkdir_toml(&path));
            } else if path.extension().and_then(|e| e.to_str()) == Some("toml") {
                files.push(path);
            }
        }
    }
    files
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE_RULE_TOML: &str = r#"
[[rules]]
id = "TEST-BEH-0001"
name = "Test behavioral rule"
enabled = true

[rules.mitre]
techniques = ["T1059.001"]

[rules.match]
type = "behavioral"
event_types = ["process.create"]

[[rules.match.conditions]]
field = "payload.process_name"
operator = "in"
values = ["powershell.exe", "cmd.exe"]

[rules.response]
severity = "HIGH"
auto_contain = ["terminate_process"]
"#;

    #[test]
    fn test_parse_behavioral_rule() {
        let rule_file: RuleFile = toml::from_str(SAMPLE_RULE_TOML).unwrap();
        assert_eq!(rule_file.rules.len(), 1);
        let rule = &rule_file.rules[0];
        assert_eq!(rule.id, "TEST-BEH-0001");
        assert_eq!(rule.response.severity, "HIGH");
    }

    #[test]
    fn test_lua_compile() {
        let mut loader = RuleLoader::new().unwrap();

        const LUA_RULE: &str = r#"
[[rules]]
id = "TEST-HEU-0001"
name = "Test Lua rule"
enabled = true

[rules.match]
type = "heuristic"
window_seconds = 10
lua_script = """
function evaluate(event, context)
  return false, {}
end
return evaluate
"""

[rules.response]
severity = "MEDIUM"
"#;
        let rule_file: RuleFile = toml::from_str(LUA_RULE).unwrap();
        for rule in rule_file.rules {
            let result = loader.compile_lua_if_needed(&rule);
            assert!(result.is_ok());
        }
    }
}
