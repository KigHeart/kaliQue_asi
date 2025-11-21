use anyhow::Result;
use pqcrypto_kyber::kyber1024;
use pqcrypto_dilithium::dilithium5;
use pqcrypto_traits::kem::{PublicKey, SecretKey, SharedSecret, Ciphertext};
use pqcrypto_traits::sign::{PublicKey as SignPublicKey, SecretKey as SignSecretKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Serialize, Deserialize)]
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

    /// Sign message using Dilithium
    pub fn dilithium_sign(&self, secret_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let sk = dilithium5::SecretKey::from_bytes(secret_key)
            .map_err(|_| anyhow::anyhow!("Invalid secret key"))?;
        
        let signature = dilithium5::sign(message, &sk);
        
        Ok(signature.as_bytes().to_vec())
    }

    /// Verify signature using Dilithium
    pub fn dilithium_verify(&self, public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool> {
        let pk = dilithium5::PublicKey::from_bytes(public_key)
            .map_err(|_| anyhow::anyhow!("Invalid public key"))?;
        let sig = dilithium5::SignedMessage::from_bytes(signature)
            .map_err(|_| anyhow::anyhow!("Invalid signature"))?;
        
        match dilithium5::open(&sig, &pk) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    pub fn get_keypair(&self, key_id: &str) -> Option<&PQCKeyPair> {
        self.key_store.get(key_id)
    }

    pub fn list_keys(&self) -> Vec<String> {
        self.key_store.keys().cloned().collect()
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
    }

    #[test]
    fn test_dilithium_signature() {
        let mut engine = PQCEngine::new();
        let keypair = engine.generate_dilithium_keypair("test_sig".to_string()).unwrap();
        
        let message = b"Test message for PQC";
        let signature = engine.dilithium_sign(&keypair.secret_key, message).unwrap();
        let valid = engine.dilithium_verify(&keypair.public_key, message, &signature).unwrap();
        
        assert!(valid);
    }
}
