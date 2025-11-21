#[cfg(feature = "python")]
use pyo3::prelude::*;
#[cfg(feature = "python")]
use pyo3::types::PyBytes;

#[cfg(feature = "python")]
#[pyclass]
pub struct PyPQCEngine {
    engine: crate::PQCEngine,
}

#[cfg(feature = "python")]
#[pymethods]
impl PyPQCEngine {
    #[new]
    fn new() -> Self {
        PyPQCEngine {
            engine: crate::PQCEngine::new(),
        }
    }

    fn generate_kyber_keypair(&mut self, key_id: String) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let keypair = self.engine.generate_kyber_keypair(key_id)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok((keypair.public_key, keypair.secret_key))
    }

    fn generate_dilithium_keypair(&mut self, key_id: String) -> PyResult<(Vec<u8>, Vec<u8>)> {
        let keypair = self.engine.generate_dilithium_keypair(key_id)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))?;
        Ok((keypair.public_key, keypair.secret_key))
    }

    fn kyber_encapsulate(&self, public_key: Vec<u8>) -> PyResult<(Vec<u8>, Vec<u8>)> {
        self.engine.kyber_encapsulate(&public_key)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn kyber_decapsulate(&self, secret_key: Vec<u8>, ciphertext: Vec<u8>) -> PyResult<Vec<u8>> {
        self.engine.kyber_decapsulate(&secret_key, &ciphertext)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn dilithium_sign(&self, secret_key: Vec<u8>, message: Vec<u8>) -> PyResult<Vec<u8>> {
        self.engine.dilithium_sign(&secret_key, &message)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }

    fn dilithium_verify(&self, public_key: Vec<u8>, signed_message: Vec<u8>) -> PyResult<Vec<u8>> {
        self.engine.dilithium_verify(&public_key, &signed_message)
            .map_err(|e| pyo3::exceptions::PyRuntimeError::new_err(e.to_string()))
    }
}

#[cfg(feature = "python")]
#[pymodule]
fn pqc_engine(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyPQCEngine>()?;
    Ok(())
}
