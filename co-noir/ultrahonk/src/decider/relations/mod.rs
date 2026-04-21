pub(crate) mod databus_lookup_relation;
pub(crate) mod delta_range_constraint_relation;
pub(crate) mod ecc_op_queue_relation;
pub(crate) mod elliptic_relation;
pub(crate) mod logderiv_lookup_relation;
pub(crate) mod memory_relation;
pub(crate) mod non_native_field_relation;
pub(crate) mod permutation_relation;
pub(crate) mod poseidon2_external_relation;
pub(crate) mod poseidon2_internal_relation;
pub(crate) mod ultra_arithmetic_relation;

use super::types::{ClaimedEvaluations, ProverUnivariates, RelationParameters};
use crate::{
    decider::relations::{
        memory_relation::{MemoryRelation, MemoryRelationAcc, MemoryRelationEvals},
        non_native_field_relation::{
            NonNativeFieldRelation, NonNativeFieldRelationAcc, NonNativeFieldRelationEvals,
        },
    },
    prelude::Univariate,
};
use ark_ff::PrimeField;
use databus_lookup_relation::{
    DatabusLookupRelation, DatabusLookupRelationAcc, DatabusLookupRelationEvals,
};
use delta_range_constraint_relation::{
    DeltaRangeConstraintRelation, DeltaRangeConstraintRelationAcc,
    DeltaRangeConstraintRelationEvals,
};
use ecc_op_queue_relation::{
    EccOpQueueRelation, EccOpQueueRelationAcc, EccOpQueueRelationEvals,
};
use elliptic_relation::{EllipticRelation, EllipticRelationAcc, EllipticRelationEvals};
use logderiv_lookup_relation::{
    LogDerivLookupRelation, LogDerivLookupRelationAcc, LogDerivLookupRelationEvals,
};
use permutation_relation::{
    UltraPermutationRelation, UltraPermutationRelationAcc, UltraPermutationRelationEvals,
};
use poseidon2_external_relation::{
    Poseidon2ExternalRelation, Poseidon2ExternalRelationAcc, Poseidon2ExternalRelationEvals,
};
use poseidon2_internal_relation::{
    Poseidon2InternalRelation, Poseidon2InternalRelationAcc, Poseidon2InternalRelationEvals,
};
use ultra_arithmetic_relation::{
    UltraArithmeticRelation, UltraArithmeticRelationAcc, UltraArithmeticRelationEvals,
};

pub(crate) trait Relation<F: PrimeField> {
    type Acc: Default;
    type VerifyAcc: Default;

    const SKIPPABLE: bool;

    fn check_skippable() {
        if !Self::SKIPPABLE {
            panic!("Cannot skip this relation");
        }
    }

    fn skip(input: &ProverUnivariates<F>) -> bool;
    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    );
}

// Ultra: 2+2+3+4+2+6+1+4+4 = 28 subrelations
// Mega adds: 8 (ecc_op) + 9 (databus) = 17
// Total: 45
pub(crate) const NUM_SUBRELATIONS: usize = UltraArithmeticRelation::NUM_RELATIONS   // 2
    + UltraPermutationRelation::NUM_RELATIONS  // 2
    + DeltaRangeConstraintRelation::NUM_RELATIONS // 4
    + EllipticRelation::NUM_RELATIONS          // 2
    + MemoryRelation::NUM_RELATIONS            // 6
    + NonNativeFieldRelation::NUM_RELATIONS    // 1
    + LogDerivLookupRelation::NUM_RELATIONS    // 3
    + Poseidon2ExternalRelation::NUM_RELATIONS // 4
    + Poseidon2InternalRelation::NUM_RELATIONS // 4
    + EccOpQueueRelation::NUM_RELATIONS        // 8 (Mega)
    + DatabusLookupRelation::NUM_RELATIONS;    // 9 (Mega)

#[derive(Default)]
pub(crate) struct AllRelationAcc<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationAcc<F>,
    pub(crate) r_perm: UltraPermutationRelationAcc<F>,
    pub(crate) r_lookup: LogDerivLookupRelationAcc<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationAcc<F>,
    pub(crate) r_elliptic: EllipticRelationAcc<F>,
    pub(crate) r_memory: MemoryRelationAcc<F>,
    pub(crate) r_nnf: NonNativeFieldRelationAcc<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationAcc<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationAcc<F>,
    // Mega-only relations
    pub(crate) r_ecc_op: EccOpQueueRelationAcc<F>,
    pub(crate) r_databus: DatabusLookupRelationAcc<F>,
}

#[derive(Default)]
pub(crate) struct AllRelationEvaluations<F: PrimeField> {
    pub(crate) r_arith: UltraArithmeticRelationEvals<F>,
    pub(crate) r_perm: UltraPermutationRelationEvals<F>,
    pub(crate) r_lookup: LogDerivLookupRelationEvals<F>,
    pub(crate) r_delta: DeltaRangeConstraintRelationEvals<F>,
    pub(crate) r_elliptic: EllipticRelationEvals<F>,
    pub(crate) r_memory: MemoryRelationEvals<F>,
    pub(crate) r_nnf: NonNativeFieldRelationEvals<F>,
    pub(crate) r_pos_ext: Poseidon2ExternalRelationEvals<F>,
    pub(crate) r_pos_int: Poseidon2InternalRelationEvals<F>,
    // Mega-only relations
    pub(crate) r_ecc_op: EccOpQueueRelationEvals<F>,
    pub(crate) r_databus: DatabusLookupRelationEvals<F>,
}

// Alpha index layout (elements[0] is the second alpha, first_scalar is alpha^0):
// Ultra:
//   arith:     [first_scalar, 0]         = 2
//   perm:      [1..3]                    = 2
//   lookup:    [3..6]                    = 3
//   delta:     [6..10]                   = 4
//   elliptic:  [10..12]                  = 2
//   memory:    [12..18]                  = 6
//   nnf:       [18..19]                  = 1
//   pos_ext:   [19..23]                  = 4
//   pos_int:   [23..27]                  = 4
// Mega additions:
//   ecc_op:    [27..35]                  = 8
//   databus:   [35..44]                  = 9

impl<F: PrimeField> AllRelationEvaluations<F> {
    pub(crate) fn scale_and_batch_elements(&self, first_scalar: F, elements: &[F]) -> F {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        let mut output = F::zero();
        self.r_arith
            .scale_and_batch_elements(&[first_scalar, elements[0]], &mut output);
        self.r_perm
            .scale_and_batch_elements(&elements[1..3], &mut output);
        self.r_lookup
            .scale_and_batch_elements(&elements[3..6], &mut output);
        self.r_delta
            .scale_and_batch_elements(&elements[6..10], &mut output);
        self.r_elliptic
            .scale_and_batch_elements(&elements[10..12], &mut output);
        self.r_memory
            .scale_and_batch_elements(&elements[12..18], &mut output);
        self.r_nnf
            .scale_and_batch_elements(&elements[18..19], &mut output);
        self.r_pos_ext
            .scale_and_batch_elements(&elements[19..23], &mut output);
        self.r_pos_int
            .scale_and_batch_elements(&elements[23..27], &mut output);
        // Mega
        self.r_ecc_op
            .scale_and_batch_elements(&elements[27..35], &mut output);
        self.r_databus
            .scale_and_batch_elements(&elements[35..44], &mut output);

        output
    }
}

impl<F: PrimeField> AllRelationAcc<F> {
    pub(crate) fn scale(&mut self, first_scalar: F, elements: &[F]) {
        assert!(elements.len() == NUM_SUBRELATIONS - 1);
        self.r_arith.scale(&[first_scalar, elements[0]]);
        self.r_perm.scale(&elements[1..3]);
        self.r_lookup.scale(&elements[3..6]);
        self.r_delta.scale(&elements[6..10]);
        self.r_elliptic.scale(&elements[10..12]);
        self.r_memory.scale(&elements[12..18]);
        self.r_nnf.scale(&elements[18..19]);
        self.r_pos_ext.scale(&elements[19..23]);
        self.r_pos_int.scale(&elements[23..27]);
        // Mega
        self.r_ecc_op.scale(&elements[27..35]);
        self.r_databus.scale(&elements[35..44]);
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        self.r_arith.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_perm.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_lookup.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_delta.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_elliptic.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_memory.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_nnf.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_pos_ext.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_pos_int.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        // Mega
        self.r_ecc_op.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
        self.r_databus.extend_and_batch_univariates(
            result, extended_random_poly, partial_evaluation_result,
        );
    }
}
