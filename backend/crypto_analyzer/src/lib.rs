use anyhow::Result;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use ignore::WalkBuilder;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CryptoUsage {
    pub file_path: String,
    pub line_number: usize,
    pub algorithm: String,
    pub usage_type: CryptoUsageType,
    pub code_snippet: String,
    pub risk_level: RiskLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum CryptoUsageType {
    KeyGeneration,
    Encryption,
    Decryption,
    Signing,
    Verification,
    KeyExchange,
    Hashing,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskLevel {
    Critical,  // Quantum-vulnerable algorithms
    High,      // Weak parameters
    Medium,    // Acceptable but needs monitoring
    Low,       // Already quantum-resistant
}

#[derive(Debug, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub total_files_scanned: usize,
    pub crypto_usages: Vec<CryptoUsage>,
    pub algorithm_summary: HashMap<String, usize>,
    pub risk_summary: HashMap<RiskLevel, usize>,
    pub recommendations: Vec<String>,
}

pub struct CryptoAnalyzer {
    patterns: Vec<CryptoPattern>,
}

#[derive(Clone)]
struct CryptoPattern {
    algorithm: String,
    pattern: Regex,
    usage_type: CryptoUsageType,
    risk_level: RiskLevel,
}

impl CryptoAnalyzer {
    pub fn new() -> Self {
        let patterns = Self::build_patterns();
        CryptoAnalyzer { patterns }
    }

    fn build_patterns() -> Vec<CryptoPattern> {
        vec![
            // RSA patterns (Critical - quantum vulnerable)
            CryptoPattern {
                algorithm: "RSA".to_string(),
                pattern: Regex::new(r"(?i)(RSA|rsa_|generateKeyPair.*RSA|RSAPublicKey|RSAPrivateKey|PKCS1|RSA-\d+)").unwrap(),
                usage_type: CryptoUsageType::KeyGeneration,
                risk_level: RiskLevel::Critical,
            },
            // ECDSA/ECC patterns (Critical - quantum vulnerable)
            CryptoPattern {
                algorithm: "ECDSA".to_string(),
                pattern: Regex::new(r"(?i)(ECDSA|EC_KEY|elliptic.*curve|secp256|prime256v1|P-256|P-384)").unwrap(),
                usage_type: CryptoUsageType::Signing,
                risk_level: RiskLevel::Critical,
            },
            // DH/ECDH patterns (Critical - quantum vulnerable)
            CryptoPattern {
                algorithm: "DH/ECDH".to_string(),
                pattern: Regex::new(r"(?i)(Diffie.*Hellman|ECDH|DHE|X25519|Curve25519)").unwrap(),
                usage_type: CryptoUsageType::KeyExchange,
                risk_level: RiskLevel::Critical,
            },
            // DSA patterns (Critical)
            CryptoPattern {
                algorithm: "DSA".to_string(),
                pattern: Regex::new(r"(?i)(DSA_|DSAPublicKey|DSAPrivateKey|Digital.*Signature.*Algorithm)").unwrap(),
                usage_type: CryptoUsageType::Signing,
                risk_level: RiskLevel::Critical,
            },
            // Post-Quantum patterns (Low risk - already safe)
            CryptoPattern {
                algorithm: "Kyber".to_string(),
                pattern: Regex::new(r"(?i)(kyber|KYBER|ml-kem)").unwrap(),
                usage_type: CryptoUsageType::KeyExchange,
                risk_level: RiskLevel::Low,
            },
            CryptoPattern {
                algorithm: "Dilithium".to_string(),
                pattern: Regex::new(r"(?i)(dilithium|DILITHIUM|ml-dsa)").unwrap(),
                usage_type: CryptoUsageType::Signing,
                risk_level: RiskLevel::Low,
            },
            CryptoPattern {
                algorithm: "SPHINCS+".to_string(),
                pattern: Regex::new(r"(?i)(sphincs|SPHINCS|slh-dsa)").unwrap(),
                usage_type: CryptoUsageType::Signing,
                risk_level: RiskLevel::Low,
            },
            // AES (Medium - quantum resistant for encryption, needs larger keys)
            CryptoPattern {
                algorithm: "AES".to_string(),
                pattern: Regex::new(r"(?i)(AES|aes_|AES-128|AES-192|AES-256)").unwrap(),
                usage_type: CryptoUsageType::Encryption,
                risk_level: RiskLevel::Medium,
            },
            // SHA-2/SHA-3 (Medium - needs monitoring)
            CryptoPattern {
                algorithm: "SHA".to_string(),
                pattern: Regex::new(r"(?i)(SHA-?256|SHA-?384|SHA-?512|SHA-?3)").unwrap(),
                usage_type: CryptoUsageType::Hashing,
                risk_level: RiskLevel::Medium,
            },
        ]
    }

    pub fn analyze_directory(&self, path: &Path) -> Result<AnalysisReport> {
        let mut usages = Vec::new();
        let mut files_scanned = 0;

        // Use ignore crate to respect .gitignore
        let walker = WalkBuilder::new(path)
            .hidden(false)
            .git_ignore(true)
            .build();

        for entry in walker.filter_map(|e| e.ok()) {
            let path = entry.path();
            
            if !path.is_file() {
                continue;
            }

            // Only analyze source code files
            if let Some(ext) = path.extension() {
                let ext_str = ext.to_string_lossy();
                if matches!(ext_str.as_ref(), "rs" | "py" | "js" | "ts" | "go" | "java" | "c" | "cpp" | "h" | "hpp") {
                    files_scanned += 1;
                    if let Ok(file_usages) = self.analyze_file(path) {
                        usages.extend(file_usages);
                    }
                }
            }
        }

        Ok(self.generate_report(files_scanned, usages))
    }

    pub fn analyze_file(&self, file_path: &Path) -> Result<Vec<CryptoUsage>> {
        let content = fs::read_to_string(file_path)?;
        let mut usages = Vec::new();

        for (line_num, line) in content.lines().enumerate() {
            for pattern in &self.patterns {
                if pattern.pattern.is_match(line) {
                    usages.push(CryptoUsage {
                        file_path: file_path.display().to_string(),
                        line_number: line_num + 1,
                        algorithm: pattern.algorithm.clone(),
                        usage_type: pattern.usage_type.clone(),
                        code_snippet: line.trim().to_string(),
                        risk_level: pattern.risk_level.clone(),
                    });
                }
            }
        }

        Ok(usages)
    }

    fn generate_report(&self, total_files: usize, usages: Vec<CryptoUsage>) -> AnalysisReport {
        let mut algorithm_summary: HashMap<String, usize> = HashMap::new();
        let mut risk_summary: HashMap<RiskLevel, usize> = HashMap::new();

        for usage in &usages {
            *algorithm_summary.entry(usage.algorithm.clone()).or_insert(0) += 1;
            *risk_summary.entry(usage.risk_level.clone()).or_insert(0) += 1;
        }

        let recommendations = self.generate_recommendations(&risk_summary, &algorithm_summary);

        AnalysisReport {
            total_files_scanned: total_files,
            crypto_usages: usages,
            algorithm_summary,
            risk_summary,
            recommendations,
        }
    }

    fn generate_recommendations(
        &self,
        risk_summary: &HashMap<RiskLevel, usize>,
        algorithm_summary: &HashMap<String, usize>,
    ) -> Vec<String> {
        let mut recommendations = Vec::new();

        if let Some(&count) = risk_summary.get(&RiskLevel::Critical) {
            if count > 0 {
                recommendations.push(format!(
                    "CRITICAL: Found {} quantum-vulnerable cryptographic implementations. Immediate migration required.",
                    count
                ));
            }
        }

        if algorithm_summary.contains_key("RSA") {
            recommendations.push(
                "Migrate RSA key exchange to Kyber (ML-KEM) for quantum resistance.".to_string()
            );
            recommendations.push(
                "Consider hybrid RSA+Kyber approach for backwards compatibility.".to_string()
            );
        }

        if algorithm_summary.contains_key("ECDSA") {
            recommendations.push(
                "Migrate ECDSA signatures to Dilithium (ML-DSA) or SPHINCS+.".to_string()
            );
        }

        if algorithm_summary.contains_key("DH/ECDH") {
            recommendations.push(
                "Replace ECDH key exchange with Kyber-1024 for post-quantum security.".to_string()
            );
        }

        if algorithm_summary.contains_key("AES") {
            recommendations.push(
                "AES-256 is quantum-resistant for encryption. Ensure key sizes are adequate (256-bit minimum).".to_string()
            );
        }

        recommendations.push(
            "Implement hybrid cryptography during transition period for maximum compatibility.".to_string()
        );

        recommendations
    }
}

impl Default for CryptoAnalyzer {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn test_rsa_detection() {
        let code = r#"
            from cryptography.hazmat.primitives.asymmetric import rsa
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        "#;
        
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.py");
        fs::write(&file_path, code).unwrap();

        let analyzer = CryptoAnalyzer::new();
        let usages = analyzer.analyze_file(&file_path).unwrap();

        assert!(!usages.is_empty());
        assert_eq!(usages[0].algorithm, "RSA");
        assert_eq!(usages[0].risk_level, RiskLevel::Critical);
    }

    #[test]
    fn test_kyber_detection() {
        let code = "use pqcrypto_kyber::kyber1024;";
        
        let temp_dir = TempDir::new().unwrap();
        let file_path = temp_dir.path().join("test.rs");
        fs::write(&file_path, code).unwrap();

        let analyzer = CryptoAnalyzer::new();
        let usages = analyzer.analyze_file(&file_path).unwrap();

        assert!(!usages.is_empty());
        assert_eq!(usages[0].algorithm, "Kyber");
        assert_eq!(usages[0].risk_level, RiskLevel::Low);
    }

    #[test]
    fn test_report_generation() {
        let analyzer = CryptoAnalyzer::new();
        let usages = vec![
            CryptoUsage {
                file_path: "test1.py".to_string(),
                line_number: 10,
                algorithm: "RSA".to_string(),
                usage_type: CryptoUsageType::KeyGeneration,
                code_snippet: "rsa.generate_private_key()".to_string(),
                risk_level: RiskLevel::Critical,
            },
            CryptoUsage {
                file_path: "test2.rs".to_string(),
                line_number: 20,
                algorithm: "Kyber".to_string(),
                usage_type: CryptoUsageType::KeyExchange,
                code_snippet: "kyber1024::keypair()".to_string(),
                risk_level: RiskLevel::Low,
            },
        ];

        let report = analyzer.generate_report(2, usages);
        
        assert_eq!(report.total_files_scanned, 2);
        assert_eq!(report.crypto_usages.len(), 2);
        assert_eq!(*report.risk_summary.get(&RiskLevel::Critical).unwrap(), 1);
        assert!(!report.recommendations.is_empty());
    }
}