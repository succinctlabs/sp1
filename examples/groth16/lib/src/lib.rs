use ark_bn254::Bn254;
use ark_ec::pairing::Pairing;
use ark_groth16::{PreparedVerifyingKey, Proof, ProvingKey};
use ark_serialize::{
    CanonicalDeserialize, CanonicalSerialize, Compress, SerializationError, Valid, Validate,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug)]
pub struct SerializableProvingKey(pub ProvingKey<Bn254>);

impl Valid for SerializableProvingKey {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for SerializableProvingKey {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl CanonicalDeserialize for SerializableProvingKey {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(SerializableProvingKey(ProvingKey::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct SerializableProof(pub Proof<Bn254>);

impl Valid for SerializableProof {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for SerializableProof {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl CanonicalDeserialize for SerializableProof {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(SerializableProof(Proof::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SerializableInputs(pub Vec<<Bn254 as Pairing>::ScalarField>);

impl Valid for SerializableInputs {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for SerializableInputs {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl CanonicalDeserialize for SerializableInputs {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(SerializableInputs(Vec::deserialize_with_mode(
            reader, compress, validate,
        )?))
    }
}

#[derive(Clone, Debug)]
pub struct SerializablePreparedVerifyingKey(pub PreparedVerifyingKey<Bn254>);

impl Valid for SerializablePreparedVerifyingKey {
    fn check(&self) -> Result<(), SerializationError> {
        Ok(())
    }
}

impl CanonicalSerialize for SerializablePreparedVerifyingKey {
    fn serialize_with_mode<W: std::io::Write>(
        &self,
        writer: W,
        compress: Compress,
    ) -> Result<(), SerializationError> {
        self.0.serialize_with_mode(writer, compress)
    }

    fn serialized_size(&self, compress: Compress) -> usize {
        self.0.serialized_size(compress)
    }
}

impl CanonicalDeserialize for SerializablePreparedVerifyingKey {
    fn deserialize_with_mode<R: std::io::Read>(
        reader: R,
        compress: Compress,
        validate: Validate,
    ) -> Result<Self, SerializationError> {
        Ok(SerializablePreparedVerifyingKey(
            PreparedVerifyingKey::deserialize_with_mode(reader, compress, validate)?,
        ))
    }
}

#[derive(Serialize, Deserialize)]
pub struct SerdeSerializableProof(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct SerdeSerializableInputs(#[serde(with = "serde_bytes")] pub Vec<u8>);

#[derive(Serialize, Deserialize)]
pub struct SerdeSerializablePreparedVerifyingKey(#[serde(with = "serde_bytes")] pub Vec<u8>);

impl From<SerializableProof> for SerdeSerializableProof {
    fn from(proof: SerializableProof) -> Self {
        let mut serialized_data = Vec::new();
        proof
            .serialize_uncompressed(&mut serialized_data)
            .expect("Serialization failed");
        SerdeSerializableProof(serialized_data)
    }
}

impl From<SerdeSerializableProof> for SerializableProof {
    fn from(proof: SerdeSerializableProof) -> Self {
        SerializableProof::deserialize_uncompressed(&mut &proof.0[..])
            .expect("Deserialization failed")
    }
}

impl From<SerializableInputs> for SerdeSerializableInputs {
    fn from(inputs: SerializableInputs) -> Self {
        let mut serialized_data = Vec::new();
        inputs
            .serialize_uncompressed(&mut serialized_data)
            .expect("Serialization failed");
        SerdeSerializableInputs(serialized_data)
    }
}

impl From<SerdeSerializableInputs> for SerializableInputs {
    fn from(inputs: SerdeSerializableInputs) -> Self {
        SerializableInputs::deserialize_uncompressed(&mut &inputs.0[..])
            .expect("Deserialization failed")
    }
}

impl From<SerializablePreparedVerifyingKey> for SerdeSerializablePreparedVerifyingKey {
    fn from(vk: SerializablePreparedVerifyingKey) -> Self {
        let mut serialized_data = Vec::new();
        vk.serialize_uncompressed(&mut serialized_data)
            .expect("Serialization failed");
        SerdeSerializablePreparedVerifyingKey(serialized_data)
    }
}

impl From<SerdeSerializablePreparedVerifyingKey> for SerializablePreparedVerifyingKey {
    fn from(vk: SerdeSerializablePreparedVerifyingKey) -> Self {
        SerializablePreparedVerifyingKey::deserialize_uncompressed(&mut &vk.0[..])
            .expect("Deserialization failed")
    }
}
