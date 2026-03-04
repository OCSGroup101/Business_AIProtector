// MITRE ATT&CK tactic/technique tag resolution

use std::collections::HashMap;

pub struct MitreTagger {
    technique_to_tactic: HashMap<&'static str, &'static str>,
}

impl MitreTagger {
    pub fn new() -> Self {
        // Subset covering Phase 1 rules — expanded in Phase 2 from STIX data
        let mut m = HashMap::new();
        m.insert("T1566.001", "TA0001"); // Initial Access — Phishing
        m.insert("T1059.001", "TA0002"); // Execution — PowerShell
        m.insert("T1059.003", "TA0002"); // Execution — cmd
        m.insert("T1059.005", "TA0002"); // Execution — VBScript
        m.insert("T1059.007", "TA0002"); // Execution — JavaScript
        m.insert("T1204.002", "TA0002"); // Execution — Malicious File
        m.insert("T1106", "TA0002");     // Execution — Native API
        m.insert("T1547.001", "TA0003"); // Persistence — Registry Run Keys
        m.insert("T1053.005", "TA0003"); // Persistence — Scheduled Task
        m.insert("T1543.003", "TA0003"); // Persistence — Windows Service
        m.insert("T1574.002", "TA0003"); // Persistence — DLL Side-Loading
        m.insert("T1548.002", "TA0004"); // Privilege Escalation — UAC Bypass
        m.insert("T1055.001", "TA0004"); // Privilege Escalation — Process Injection
        m.insert("T1078", "TA0004");     // Privilege Escalation — Valid Accounts
        m.insert("T1036.005", "TA0005"); // Defense Evasion — Match Legitimate Name
        m.insert("T1070.001", "TA0005"); // Defense Evasion — Clear Windows Event Logs
        m.insert("T1562.001", "TA0005"); // Defense Evasion — Disable Security Tools
        m.insert("T1027", "TA0005");     // Defense Evasion — Obfuscated Files
        m.insert("T1003.001", "TA0006"); // Credential Access — LSASS Memory
        m.insert("T1110.001", "TA0006"); // Credential Access — Brute Force
        m.insert("T1552.001", "TA0006"); // Credential Access — Credentials in Files
        m.insert("T1082", "TA0007");     // Discovery — System Information
        m.insert("T1016", "TA0007");     // Discovery — System Network Config
        m.insert("T1087.002", "TA0007"); // Discovery — Domain Account
        m.insert("T1021.001", "TA0008"); // Lateral Movement — RDP
        m.insert("T1021.002", "TA0008"); // Lateral Movement — SMB
        m.insert("T1550.002", "TA0008"); // Lateral Movement — Pass the Hash
        m.insert("T1560.001", "TA0009"); // Collection — Archive via Utility
        m.insert("T1074.001", "TA0009"); // Collection — Local Data Staging
        m.insert("T1071.001", "TA0011"); // C2 — Web Protocols
        m.insert("T1105", "TA0011");     // C2 — Ingress Tool Transfer
        m.insert("T1573.002", "TA0011"); // C2 — Asymmetric Cryptography
        m.insert("T1041", "TA0010");     // Exfiltration — Exfil Over C2
        m.insert("T1048.003", "TA0010"); // Exfiltration — DNS
        m.insert("T1486", "TA0040");     // Impact — Data Encrypted for Impact (Ransomware)
        m.insert("T1490", "TA0040");     // Impact — Inhibit System Recovery
        Self { technique_to_tactic: m }
    }

    /// Generate MITRE tags for a list of technique IDs.
    pub fn tags_for_techniques(&self, techniques: &[String]) -> Vec<String> {
        let mut tags = Vec::new();
        let mut tactics_seen = std::collections::HashSet::new();
        for technique in techniques {
            tags.push(format!("mitre:{}", technique));
            if let Some(tactic) = self.technique_to_tactic.get(technique.as_str()) {
                if tactics_seen.insert(*tactic) {
                    tags.push(format!("mitre:{}", tactic));
                }
            }
        }
        tags
    }
}

impl Default for MitreTagger {
    fn default() -> Self { Self::new() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_technique_lookup() {
        let tagger = MitreTagger::new();
        let tags = tagger.tags_for_techniques(&["T1059.001".to_string()]);
        assert!(tags.contains(&"mitre:T1059.001".to_string()));
        assert!(tags.contains(&"mitre:TA0002".to_string()));
    }

    #[test]
    fn test_unknown_technique_still_tagged() {
        let tagger = MitreTagger::new();
        let tags = tagger.tags_for_techniques(&["T9999.999".to_string()]);
        assert!(tags.contains(&"mitre:T9999.999".to_string()));
    }
}
