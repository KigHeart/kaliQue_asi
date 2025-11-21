{
  "total_files_scanned": 6,
  "crypto_usages": [
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 69,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "// RSA patterns (Critical - quantum vulnerable)",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 71,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "algorithm: \"RSA\".to_string(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 72,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "pattern: Regex::new(r\"(?i)(RSA|rsa_|generateKeyPair.*RSA|RSAPublicKey|RSAPrivateKey|PKCS1|RSA-\\d+)\").unwrap(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 76,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "// ECDSA/ECC patterns (Critical - quantum vulnerable)",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 78,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "algorithm: \"ECDSA\".to_string(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 79,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "pattern: Regex::new(r\"(?i)(ECDSA|EC_KEY|elliptic.*curve|secp256|prime256v1|P-256|P-384)\").unwrap(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 83,
      "algorithm": "DH/ECDH",
      "usage_type": "KeyExchange",
      "code_snippet": "// DH/ECDH patterns (Critical - quantum vulnerable)",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 85,
      "algorithm": "DH/ECDH",
      "usage_type": "KeyExchange",
      "code_snippet": "algorithm: \"DH/ECDH\".to_string(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 86,
      "algorithm": "DH/ECDH",
      "usage_type": "KeyExchange",
      "code_snippet": "pattern: Regex::new(r\"(?i)(Diffie.*Hellman|ECDH|DHE|X25519|Curve25519)\").unwrap(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 93,
      "algorithm": "DSA",
      "usage_type": "Signing",
      "code_snippet": "pattern: Regex::new(r\"(?i)(DSA_|DSAPublicKey|DSAPrivateKey|Digital.*Signature.*Algorithm)\").unwrap(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 99,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "algorithm: \"Kyber\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 100,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "pattern: Regex::new(r\"(?i)(kyber|KYBER|ml-kem)\").unwrap(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 105,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "algorithm: \"Dilithium\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 106,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "pattern: Regex::new(r\"(?i)(dilithium|DILITHIUM|ml-dsa)\").unwrap(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 111,
      "algorithm": "SPHINCS+",
      "usage_type": "Signing",
      "code_snippet": "algorithm: \"SPHINCS+\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 112,
      "algorithm": "SPHINCS+",
      "usage_type": "Signing",
      "code_snippet": "pattern: Regex::new(r\"(?i)(sphincs|SPHINCS|slh-dsa)\").unwrap(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 116,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "// AES (Medium - quantum resistant for encryption, needs larger keys)",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 118,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "algorithm: \"AES\".to_string(),",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 119,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "pattern: Regex::new(r\"(?i)(AES|aes_|AES-128|AES-192|AES-256)\").unwrap(),",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 123,
      "algorithm": "SHA",
      "usage_type": "Hashing",
      "code_snippet": "// SHA-2/SHA-3 (Medium - needs monitoring)",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 223,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "if algorithm_summary.contains_key(\"RSA\") {",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 225,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "\"Migrate RSA key exchange to Kyber (ML-KEM) for quantum resistance.\".to_string()",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 225,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "\"Migrate RSA key exchange to Kyber (ML-KEM) for quantum resistance.\".to_string()",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 228,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "\"Consider hybrid RSA+Kyber approach for backwards compatibility.\".to_string()",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 228,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "\"Consider hybrid RSA+Kyber approach for backwards compatibility.\".to_string()",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 232,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "if algorithm_summary.contains_key(\"ECDSA\") {",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 234,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "\"Migrate ECDSA signatures to Dilithium (ML-DSA) or SPHINCS+.\".to_string()",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 234,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "\"Migrate ECDSA signatures to Dilithium (ML-DSA) or SPHINCS+.\".to_string()",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 234,
      "algorithm": "SPHINCS+",
      "usage_type": "Signing",
      "code_snippet": "\"Migrate ECDSA signatures to Dilithium (ML-DSA) or SPHINCS+.\".to_string()",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 238,
      "algorithm": "DH/ECDH",
      "usage_type": "KeyExchange",
      "code_snippet": "if algorithm_summary.contains_key(\"DH/ECDH\") {",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 240,
      "algorithm": "DH/ECDH",
      "usage_type": "KeyExchange",
      "code_snippet": "\"Replace ECDH key exchange with Kyber-1024 for post-quantum security.\".to_string()",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 240,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "\"Replace ECDH key exchange with Kyber-1024 for post-quantum security.\".to_string()",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 244,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "if algorithm_summary.contains_key(\"AES\") {",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 246,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "\"AES-256 is quantum-resistant for encryption. Ensure key sizes are adequate (256-bit minimum).\".to_string()",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 271,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "fn test_rsa_detection() {",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 273,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "from cryptography.hazmat.primitives.asymmetric import rsa",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 274,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 285,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "assert_eq!(usages[0].algorithm, \"RSA\");",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 290,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "fn test_kyber_detection() {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 291,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let code = \"use pqcrypto_kyber::kyber1024;\";",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 301,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "assert_eq!(usages[0].algorithm, \"Kyber\");",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 312,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "algorithm: \"RSA\".to_string(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 314,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "code_snippet: \"rsa.generate_private_key()\".to_string(),",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 320,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "algorithm: \"Kyber\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\crypto_analyzer\\src\\lib.rs",
      "line_number": 322,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "code_snippet: \"kyber1024::keypair()\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 7,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "use pqcrypto_kyber::kyber1024;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 8,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "use pqcrypto_dilithium::dilithium5;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 41,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "/// Generate Kyber-1024 key pair for KEM",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 42,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "pub fn generate_kyber_keypair(&mut self, key_id: String) -> Result<PQCKeyPair> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 43,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let (pk, sk) = kyber1024::keypair();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 46,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "algorithm: \"Kyber-1024\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 55,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "/// Generate Dilithium-5 key pair for signatures",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 56,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "pub fn generate_dilithium_keypair(&mut self, key_id: String) -> Result<PQCKeyPair> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 57,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let (pk, sk) = dilithium5::keypair();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 60,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "algorithm: \"Dilithium-5\".to_string(),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 69,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "/// Encapsulate shared secret using Kyber",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 70,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "pub fn kyber_encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 71,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let pk = kyber1024::PublicKey::from_bytes(public_key)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 74,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let (ss, ct) = kyber1024::encapsulate(&pk);",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 79,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "/// Decapsulate shared secret using Kyber",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 80,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "pub fn kyber_decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 81,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let sk = kyber1024::SecretKey::from_bytes(secret_key)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 83,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let ct = kyber1024::Ciphertext::from_bytes(ciphertext)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 86,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let ss = kyber1024::decapsulate(&ct, &sk);",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 91,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "/// Sign message using Dilithium (returns detached signature + message)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 92,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "pub fn dilithium_sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 93,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let sk = dilithium5::SecretKey::from_bytes(secret_key)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 96,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let signed_msg = dilithium5::sign(message, &sk);",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 102,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "/// Verify signature using Dilithium",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 103,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "pub fn dilithium_verify(&self, public_key: &[u8], signed_message: &[u8]) -> Result<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 104,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let pk = dilithium5::PublicKey::from_bytes(public_key)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 106,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let sig = dilithium5::SignedMessage::from_bytes(signed_message)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 110,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "match dilithium5::open(&sig, &pk) {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 136,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "fn test_kyber_kem() {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 138,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let keypair = engine.generate_kyber_keypair(\"test_key\".to_string()).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 140,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let (ss1, ct) = engine.kyber_encapsulate(&keypair.public_key).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 141,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let ss2 = engine.kyber_decapsulate(&keypair.secret_key, &ct).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 144,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "println!(\"✓ Kyber KEM test passed - shared secret length: {}\", ss1.len());",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 148,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "fn test_dilithium_signature() {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 150,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let keypair = engine.generate_dilithium_keypair(\"test_sig\".to_string()).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 153,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let signed_msg = engine.dilithium_sign(&keypair.secret_key, message).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 154,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let verified_msg = engine.dilithium_verify(&keypair.public_key, &signed_msg).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 157,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "println!(\"✓ Dilithium signature test passed\");",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 164,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "engine.generate_kyber_keypair(\"kyber_1\".to_string()).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 165,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "engine.generate_dilithium_keypair(\"dilithium_1\".to_string()).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 169,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "assert!(keys.contains(&\"kyber_1\".to_string()));",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 170,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "assert!(keys.contains(&\"dilithium_1\".to_string()));",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 178,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let keypair = engine.generate_dilithium_keypair(\"test_invalid\".to_string()).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 181,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let signed_msg = engine.dilithium_sign(&keypair.secret_key, message).unwrap();",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\lib.rs",
      "line_number": 189,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let result = engine.dilithium_verify(&keypair.public_key, &corrupted);",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 22,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "fn generate_kyber_keypair(&mut self, key_id: String) -> PyResult<(Vec<u8>, Vec<u8>)> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 23,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let keypair = self.engine.generate_kyber_keypair(key_id)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 28,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "fn generate_dilithium_keypair(&mut self, key_id: String) -> PyResult<(Vec<u8>, Vec<u8>)> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 29,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let keypair = self.engine.generate_dilithium_keypair(key_id)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 34,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "fn kyber_encapsulate(&self, public_key: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 35,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "self.engine.kyber_encapsulate(&public_key)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 39,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "fn kyber_decapsulate(&self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 40,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "self.engine.kyber_decapsulate(&secret_key, &ciphertext)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 44,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "fn dilithium_sign(&self, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 45,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "self.engine.dilithium_sign(&secret_key, &message)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 49,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "fn dilithium_verify(&self, public_key: Vec<u8>, signed_message: Vec<u8>) -> PyResult<Vec<u8>> {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\backend\\pqc_engine\\src\\python_bindings.rs",
      "line_number": 50,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "self.engine.dilithium_verify(&public_key, &signed_message)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 33,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "/// Algorithm (kyber, dilithium)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 33,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "/// Algorithm (kyber, dilithium)",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 157,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "\"kyber\" => {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 158,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "println!(\"  Algorithm: Kyber-1024 (ML-KEM)\");",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 159,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "engine.generate_kyber_keypair(id.clone())?",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 161,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "\"dilithium\" => {",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 162,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "println!(\"  Algorithm: Dilithium-5 (ML-DSA)\");",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 163,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "engine.generate_dilithium_keypair(id.clone())?",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 165,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "_ => anyhow::bail!(\"Unknown algorithm: {}. Use 'kyber' or 'dilithium'\", algorithm),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 165,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "_ => anyhow::bail!(\"Unknown algorithm: {}. Use 'kyber' or 'dilithium'\", algorithm),",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 171,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "let sec_key_path = output.join(format!(\"{}_secret.key\", id));",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 174,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "std::fs::write(&sec_key_path, &keypair.secret_key)?;",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 178,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "println!(\"  Secret key: {} ({} bytes)\", sec_key_path.display(), keypair.secret_key.len());",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 212,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "- Develop Kyber-1024 integration",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 213,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "- Develop Dilithium-5 integration",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 264,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "println!(\"{}\", \"Testing Kyber-1024 KEM...\".bright_blue());",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 272,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let keypair = engine.generate_kyber_keypair(\"test_kem\".to_string())?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 276,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let (ss1, ct) = engine.kyber_encapsulate(&keypair.public_key)?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 280,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "let ss2 = engine.kyber_decapsulate(&keypair.secret_key, &ct)?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 295,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "println!(\"{}\", \"Testing Dilithium-5 Signatures...\".bright_blue());",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 303,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let keypair = engine.generate_dilithium_keypair(\"test_sig\".to_string())?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 309,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let signed_msg = engine.dilithium_sign(&keypair.secret_key, message)?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\cli\\src\\main.rs",
      "line_number": 313,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "let verified = engine.dilithium_verify(&keypair.public_key, &signed_msg)?;",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 336,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "current_algorithm=\"RSA-2048\",",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 337,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "target_algorithm=\"Kyber-1024\",",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 346,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "current_algorithm=\"ECDSA-P256\",",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 347,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "target_algorithm=\"Dilithium-5\",",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 356,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "current_algorithm=\"AES-256-GCM\",",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\migration_planner\\migration_planner.py",
      "line_number": 357,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "target_algorithm=\"AES-256-GCM\",",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 198,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "current_crypto=[\"RSA-2048\", \"ECDSA-P256\", \"AES-256-GCM\"],",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 198,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "current_crypto=[\"RSA-2048\", \"ECDSA-P256\", \"AES-256-GCM\"],",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 198,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "current_crypto=[\"RSA-2048\", \"ECDSA-P256\", \"AES-256-GCM\"],",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 199,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "target_crypto=[\"Kyber-1024\", \"Dilithium-5\", \"AES-256-GCM\"],",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 199,
      "algorithm": "Dilithium",
      "usage_type": "Signing",
      "code_snippet": "target_crypto=[\"Kyber-1024\", \"Dilithium-5\", \"AES-256-GCM\"],",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 199,
      "algorithm": "AES",
      "usage_type": "Encryption",
      "code_snippet": "target_crypto=[\"Kyber-1024\", \"Dilithium-5\", \"AES-256-GCM\"],",
      "risk_level": "Medium"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 209,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "description=\"Analyze current RSA and ECDSA usage patterns\",",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 209,
      "algorithm": "ECDSA",
      "usage_type": "Signing",
      "code_snippet": "description=\"Analyze current RSA and ECDSA usage patterns\",",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 216,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "description=\"Create migration plan for Kyber KEM integration\",",
      "risk_level": "Low"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 223,
      "algorithm": "RSA",
      "usage_type": "KeyGeneration",
      "code_snippet": "description=\"Generate code for hybrid RSA/Kyber implementation\",",
      "risk_level": "Critical"
    },
    {
      "file_path": "E:\\kaliQue_asi\\frontend\\orchestrator\\agent_coordinator.py",
      "line_number": 223,
      "algorithm": "Kyber",
      "usage_type": "KeyExchange",
      "code_snippet": "description=\"Generate code for hybrid RSA/Kyber implementation\",",
      "risk_level": "Low"
    }
  ],
  "algorithm_summary": {
    "AES": 9,
    "Kyber": 51,
    "RSA": 16,
    "DSA": 1,
    "Dilithium": 45,
    "SPHINCS+": 3,
    "ECDSA": 11,
    "DH/ECDH": 5,
    "SHA": 1
  },
  "risk_summary": {
    "Low": 99,
    "Critical": 33,
    "Medium": 10
  },
  "recommendations": [
    "CRITICAL: Found 33 quantum-vulnerable cryptographic implementations. Immediate migration required.",
    "Migrate RSA key exchange to Kyber (ML-KEM) for quantum resistance.",
    "Consider hybrid RSA+Kyber approach for backwards compatibility.",
    "Migrate ECDSA signatures to Dilithium (ML-DSA) or SPHINCS+.",
    "Replace ECDH key exchange with Kyber-1024 for post-quantum security.",
    "AES-256 is quantum-resistant for encryption. Ensure key sizes are adequate (256-bit minimum).",
    "Implement hybrid cryptography during transition period for maximum compatibility."
  ]
}