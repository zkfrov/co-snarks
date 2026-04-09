use crate::{
    honk_verifier::verifier_relations::NUM_SUBRELATIONS,
    prelude::RecursiveVerificationKey,
    types::{big_group::BigGroup, field_ct::FieldCT},
};
use co_acvm::mpc::NoirWitnessExtensionProtocol;
use co_noir_common::{
    honk_curve::HonkCurve, honk_proof::TranscriptFieldType, polynomials::entities::WitnessEntities,
    types::RelationParameters,
};

pub type WitnessCommitments<C, T> = WitnessEntities<BigGroup<C, T>>;

pub(crate) struct RecursiveDeciderVerificationKey<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) vk_and_hash: VKAndHash<C, T>,
    pub(crate) _is_complete: bool,
    pub(crate) public_inputs: Vec<FieldCT<C::ScalarField>>,
    pub(crate) alphas: [FieldCT<C::ScalarField>; NUM_SUBRELATIONS - 1],
    pub(crate) gate_challenges: Vec<FieldCT<C::ScalarField>>,
    pub(crate) relation_parameters: RelationParameters<FieldCT<C::ScalarField>>,
    pub(crate) target_sum: FieldCT<C::ScalarField>,
    pub(crate) witness_commitments: WitnessCommitments<C::ScalarField, T>,
    /// ZK: Gemini masking polynomial commitment received in oink
    pub(crate) gemini_masking_commitment: Option<BigGroup<C::ScalarField, T>>,
    /// ZK: Gemini masking polynomial evaluation from sumcheck evaluations (index 0)
    pub(crate) gemini_masking_poly_eval: Option<FieldCT<C::ScalarField>>,
}

pub(crate) struct VKAndHash<
    C: HonkCurve<TranscriptFieldType>,
    T: NoirWitnessExtensionProtocol<C::ScalarField>,
> {
    pub(crate) vk: RecursiveVerificationKey<C, T>,
    pub(crate) hash: FieldCT<C::ScalarField>,
}
