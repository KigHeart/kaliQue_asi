#[cfg(feature = "python")]
mod python_bindings;
#[cfg(feature = "python")]
pub use python_bindings::*;

use anyhow::Result;
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey, SignedMessage};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PQCKeyPair {
    pub algorithm: String,
    pub public_key: Vec<u8>,
    pub secret_key: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MigrationTask {
    pub task_id: String,
    pub source_algorithm: String,
    pub target_algorithm: String,
    pub priority: u8,
    pub status: String,
}

pub struct PQCEngine {
    key_store: HashMap<String, PQCKeyPair>,
}

impl PQCEngine {
    pub fn new() -> Self {
        PQCEngine {
            key_store: HashMap::new(),
        }
    }

    /// Generate Kyber-1024 key pair for KEM
    pub fn generate_kyber_keypair(&mut self, key_id: String) -> Result<PQCKeyPair> {
        let (pk, sk) = kyber1024::keypair();
        
        let keypair = PQCKeyPair {
            algorithm: "Kyber-1024".to_string(),
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        };
        
        self.key_store.insert(key_id, keypair.clone());
        Ok(keypair)
    }

    /// Generate Dilithium-5 key pair for signatures
    pub fn generate_dilithium_keypair(&mut self, key_id: String) -> Result<PQCKeyPair> {
        let (pk, sk) = dilithium5::keypair();
        
        let keypair = PQCKeyPair {
            algorithm: "Dilithium-5".to_string(),
            public_key: pk.as_bytes().to_vec(),
            secret_key: sk.as_bytes().to_vec(),
        };
        
        self.key_store.insert(key_id, keypair.clone());
        Ok(keypair)
    }

    /// Encapsulate shared secret using Kyber
    pub fn kyber_encapsulate(&self, public_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let pk = kyber1024::PublicKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        
        let (ss, ct) = kyber1024::encapsulate(&pk);
        
        Ok((ss.as_bytes().to_vec(), ct.as_bytes().to_vec()))
    }

    /// Decapsulate shared secret using Kyber
    pub fn kyber_decapsulate(&self, secret_key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>> {
        let sk = kyber1024::SecretKey::from_bytes(secret_key)
            .map_err(|_| anyhow::anyhow!("Invalid secret key"))?;
        let ct = kyber1024::Ciphertext::from_bytes(ciphertext)
            .map_err(|_| anyhow::anyhow!("Invalid ciphertext"))?;
        
        let ss = kyber1024::decapsulate(&ct, &sk);
        
        Ok(ss.as_bytes().to_vec())
    }

    /// Sign message using Dilithium (returns detached signature + message)
    pub fn dilithium_sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium5::SecretKey::from_bytes(secret_key)
            .map_err(|_| anyhow::anyhow!("Invalid secret key"))?;
        
        let signed_msg = dilithium5::sign(message, &sk);
        
        // Return the complete signed message (includes signature)
        Ok(signed_msg.as_bytes().to_vec())
    }

    /// Verify signature using Dilithium
    pub fn dilithium_verify(&self, public_key: &[u8], signed_message: &[u8]) -> Result<Vec<u8>> {
        let pk = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        let sig = dilithium5::SignedMessage::from_bytes(signed_message)
            .map_err(|_| anyhow::anyhow!("Invalid signed message"))?;
        
        // Open returns the original message if signature is valid
        match dilithium5::open(&sig, &pk) {
            Ok(msg) => Ok(msg.to_vec()),
            Err(_) => Err(anyhow::anyhow!("Signature verification failed")),
        }
    }

    pub fn get_keypair(&self, key_id: &str) -> Option<&PQCKeyPair> {
        self.key_store.get(key_id)
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.key_store.keys().cloned().collect()
    }
}

impl Default for PQCEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kyber_kem() {
        let mut engine = PQCEngine::new();
        let keypair = engine.generate_kyber_keypair("test_key".to_string()).unwrap();
        
        let (ss1, ct) = engine.kyber_encapsulate(&keypair.public_key).unwrap();
        let ss2 = engine.kyber_decapsulate(&keypair.secret_key, &ct).unwrap();
        
        assert_eq!(ss1, ss2);
        println!("✓ Kyber KEM test passed - shared secret length: {}", ss1.len());
    }

    #[test]
    fn test_dilithium_signature() {
        let mut engine = PQCEngine::new();
        let keypair = engine.generate_dilithium_keypair("test_sig".to_string()).unwrap();
        
        let message = b"Test message for PQC migration";
        let signed_msg = engine.dilithium_sign(&keypair.secret_key, message).unwrap();
        let verified_msg = engine.dilithium_verify(&keypair.public_key, &signed_msg).unwrap();
        
        assert_eq!(message.to_vec(), verified_msg);
        println!("✓ Dilithium signature test passed");
    }

    #[test]
    fn test_key_storage() {
        let mut engine = PQCEngine::new();
        
        engine.generate_kyber_keypair("kyber_1".to_string()).unwrap();
        engine.generate_dilithium_keypair("dilithium_1".to_string()).unwrap();
        
        let keys = engine.list_keys();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains(&"kyber_1".to_string()));
        assert!(keys.contains(&"dilithium_1".to_string()));
        
        println!("✓ Key storage test passed");
    }

    #[test]
    fn test_invalid_signature() {
        let mut engine = PQCEngine::new();
        let keypair = engine.generate_dilithium_keypair("test_invalid".to_string()).unwrap();
        
        let message = b"Original message";
        let signed_msg = engine.dilithium_sign(&keypair.secret_key, message).unwrap();
        
        // Corrupt the signed message
        let mut corrupted = signed_msg.clone();
        if let Some(byte) = corrupted.get_mut(10) {
            *byte = byte.wrapping_add(1);
        }
        
        let result = engine.dilithium_verify(&keypair.public_key, &corrupted);
        assert!(result.is_err());
        println!("✓ Invalid signature detection test passed");
    }
}