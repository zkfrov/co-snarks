// ECC Op Queue Relation for MegaFlavor
//
// Constrains ecc_op_wire polynomials to equal shifted wires on the ECC op domain,
// and zero elsewhere. 8 subrelations, all degree 3.
//
// Reference: barretenberg/relations/ecc_op_queue_relation.hpp

use crate::decider::types::{ClaimedEvaluations, RelationParameters};
use crate::decider::{types::ProverUnivariates, univariate::Univariate};
use ark_ff::{PrimeField, Zero};

#[derive(Clone, Debug, Default)]
pub(crate) struct EccOpQueueRelationAcc<F: PrimeField> {
    pub(crate) r0: Univariate<F, 3>,
    pub(crate) r1: Univariate<F, 3>,
    pub(crate) r2: Univariate<F, 3>,
    pub(crate) r3: Univariate<F, 3>,
    pub(crate) r4: Univariate<F, 3>,
    pub(crate) r5: Univariate<F, 3>,
    pub(crate) r6: Univariate<F, 3>,
    pub(crate) r7: Univariate<F, 3>,
}

impl<F: PrimeField> EccOpQueueRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == EccOpQueueRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
        self.r6 *= elements[6];
        self.r7 *= elements[7];
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        self.r0.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r1.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r2.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r3.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r4.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r5.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r6.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r7.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct EccOpQueueRelationEvals<F: PrimeField> {
    pub(crate) r0: F, pub(crate) r1: F, pub(crate) r2: F, pub(crate) r3: F,
    pub(crate) r4: F, pub(crate) r5: F, pub(crate) r6: F, pub(crate) r7: F,
}

impl<F: PrimeField> EccOpQueueRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == EccOpQueueRelation::NUM_RELATIONS);
        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
        *result += self.r4 * running_challenge[4];
        *result += self.r5 * running_challenge[5];
        *result += self.r6 * running_challenge[6];
        *result += self.r7 * running_challenge[7];
    }
}

pub(crate) struct EccOpQueueRelation {}

impl EccOpQueueRelation {
    pub(crate) const NUM_RELATIONS: usize = 8;
}

impl<F: PrimeField> super::Relation<F> for EccOpQueueRelation {
    type Acc = EccOpQueueRelationAcc<F>;
    type VerifyAcc = EccOpQueueRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        input.precomputed.lagrange_ecc_op().is_zero()
    }

    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        let w_1_shift = input.shifted_witness.w_l();
        let w_2_shift = input.shifted_witness.w_r();
        let w_3_shift = input.shifted_witness.w_o();
        let w_4_shift = input.shifted_witness.w_4();
        let op_wire_1 = input.witness.ecc_op_wire_1();
        let op_wire_2 = input.witness.ecc_op_wire_2();
        let op_wire_3 = input.witness.ecc_op_wire_3();
        let op_wire_4 = input.witness.ecc_op_wire_4();
        let lagrange_ecc_op = input.precomputed.lagrange_ecc_op();

        // lagrange_by_scaling = lagrange_ecc_op * scaling_factor
        let lagrange_by_scaling = lagrange_ecc_op.to_owned() * scaling_factor;
        // complement = scaling_factor - lagrange_by_scaling
        let complement_by_scaling = -(lagrange_by_scaling.to_owned()) + scaling_factor;

        // Subrelations 0-3: (op_wire_i - w_i_shift) * lagrange * scaling
        let tmp = (op_wire_1.to_owned() - w_1_shift) * &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r0.evaluations.len() { univariate_accumulator.r0.evaluations[i] += tmp.evaluations[i]; }
        let tmp = (op_wire_2.to_owned() - w_2_shift) * &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r1.evaluations.len() { univariate_accumulator.r1.evaluations[i] += tmp.evaluations[i]; }
        let tmp = (op_wire_3.to_owned() - w_3_shift) * &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r2.evaluations.len() { univariate_accumulator.r2.evaluations[i] += tmp.evaluations[i]; }
        let tmp = (op_wire_4.to_owned() - w_4_shift) * &lagrange_by_scaling;
        for i in 0..univariate_accumulator.r3.evaluations.len() { univariate_accumulator.r3.evaluations[i] += tmp.evaluations[i]; }

        // Subrelations 4-7: op_wire_i * complement * scaling
        let tmp = op_wire_1.to_owned() * &complement_by_scaling;
        for i in 0..univariate_accumulator.r4.evaluations.len() { univariate_accumulator.r4.evaluations[i] += tmp.evaluations[i]; }
        let tmp = op_wire_2.to_owned() * &complement_by_scaling;
        for i in 0..univariate_accumulator.r5.evaluations.len() { univariate_accumulator.r5.evaluations[i] += tmp.evaluations[i]; }
        let tmp = op_wire_3.to_owned() * &complement_by_scaling;
        for i in 0..univariate_accumulator.r6.evaluations.len() { univariate_accumulator.r6.evaluations[i] += tmp.evaluations[i]; }
        let tmp = op_wire_4.to_owned() * &complement_by_scaling;
        for i in 0..univariate_accumulator.r7.evaluations.len() { univariate_accumulator.r7.evaluations[i] += tmp.evaluations[i]; }
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F>,
        _relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        let w_1_shift = *input.shifted_witness.w_l();
        let w_2_shift = *input.shifted_witness.w_r();
        let w_3_shift = *input.shifted_witness.w_o();
        let w_4_shift = *input.shifted_witness.w_4();
        let op_wire_1 = *input.witness.ecc_op_wire_1();
        let op_wire_2 = *input.witness.ecc_op_wire_2();
        let op_wire_3 = *input.witness.ecc_op_wire_3();
        let op_wire_4 = *input.witness.ecc_op_wire_4();
        let lagrange_ecc_op = *input.precomputed.lagrange_ecc_op();

        let lagrange_by_scaling = lagrange_ecc_op * scaling_factor;
        let complement_by_scaling = *scaling_factor - lagrange_by_scaling;

        univariate_accumulator.r0 += (op_wire_1 - w_1_shift) * lagrange_by_scaling;
        univariate_accumulator.r1 += (op_wire_2 - w_2_shift) * lagrange_by_scaling;
        univariate_accumulator.r2 += (op_wire_3 - w_3_shift) * lagrange_by_scaling;
        univariate_accumulator.r3 += (op_wire_4 - w_4_shift) * lagrange_by_scaling;

        univariate_accumulator.r4 += op_wire_1 * complement_by_scaling;
        univariate_accumulator.r5 += op_wire_2 * complement_by_scaling;
        univariate_accumulator.r6 += op_wire_3 * complement_by_scaling;
        univariate_accumulator.r7 += op_wire_4 * complement_by_scaling;
    }
}
