use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};

use ctutils::CtEq;
use quinn_proto::crypto;

pub(crate) struct Blake3Prk(pub(crate) [u8; 32]);

impl Blake3Prk {
    pub fn new(rng: &mut impl rand::RngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self(key)
    }
}

impl crypto::HandshakeTokenKey for Blake3Prk {
    fn aead_from_hkdf(&self, random_bytes: &[u8]) -> Box<dyn crypto::AeadKey> {
        let okm = blake3::keyed_hash(&self.0, random_bytes);
        let aead = Aes256Gcm::new(okm.as_bytes().into());
        Box::new(AesGcmAeadKey(aead))
    }
}

pub(crate) struct AesGcmAeadKey(Aes256Gcm);

impl crypto::AeadKey for AesGcmAeadKey {
    fn seal(&self, data: &mut Vec<u8>, additional_data: &[u8]) -> Result<(), crypto::CryptoError> {
        // TODO(matheus23): Find some reference as to why the fuck this is a zeroed nonce
        let zero_nonce = aes_gcm::Nonce::from([0u8; 12]);
        self.0
            .encrypt_in_place(&zero_nonce, additional_data, data)
            .map_err(|_| crypto::CryptoError)?;
        Ok(())
    }

    fn open<'a>(
        &self,
        data: &'a mut [u8],
        additional_data: &[u8],
    ) -> Result<&'a mut [u8], crypto::CryptoError> {
        let (data, tag) = data
            .split_last_chunk_mut::<16>()
            .ok_or(crypto::CryptoError)?;
        let zero_nonce = aes_gcm::Nonce::from([0u8; 12]);
        let tag = aes_gcm::Tag::from_slice(tag);
        self.0
            .decrypt_in_place_detached(&zero_nonce, additional_data, data, tag)
            .map_err(|_| crypto::CryptoError)?;
        Ok(data)
    }
}

pub(crate) struct Blake3HmacKey([u8; 32]);

impl Blake3HmacKey {
    pub fn new(rng: &mut impl rand::RngCore) -> Self {
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        Self(key)
    }
}

impl quinn::crypto::HmacKey for Blake3HmacKey {
    fn sign(&self, data: &[u8], signature_out: &mut [u8]) {
        signature_out.copy_from_slice(blake3::keyed_hash(&self.0, data).as_slice());
    }

    fn signature_len(&self) -> usize {
        blake3::OUT_LEN // 32 bytes
    }

    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<(), quinn::crypto::CryptoError> {
        let reference = blake3::keyed_hash(&self.0, data);
        // to_bool is fine here, because it's the last thing we do to
        // distinguish success or failure (see to_bool documentation)
        if signature.ct_eq(reference.as_slice()).to_bool() {
            Ok(())
        } else {
            Err(quinn::crypto::CryptoError)
        }
    }
}
