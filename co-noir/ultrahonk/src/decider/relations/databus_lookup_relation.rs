// Databus Lookup Relation for MegaFlavor
//
// Log-derivative lookup for 3 bus columns × 3 subrelations = 9 total.
// Reference: barretenberg/relations/databus_lookup_relation.hpp

use super::Relation;
use crate::decider::{
    types::{ClaimedEvaluations, ProverUnivariates, RelationParameters},
    univariate::Univariate,
};
use ark_ff::{PrimeField, Zero};
use co_noir_common::constants::MAX_PARTIAL_RELATION_LENGTH;

type Uni<F> = Univariate<F, MAX_PARTIAL_RELATION_LENGTH>;

#[derive(Clone, Debug, Default)]
pub(crate) struct DatabusLookupRelationAcc<F: PrimeField> {
    // Bus column 0 (calldata)
    pub(crate) r0: Univariate<F, 5>, // inverse correctness
    pub(crate) r1: Univariate<F, 5>, // lookup identity (linearly dependent)
    pub(crate) r2: Univariate<F, 3>, // read_tag boolean check
    // Bus column 1 (secondary_calldata)
    pub(crate) r3: Univariate<F, 5>,
    pub(crate) r4: Univariate<F, 5>,
    pub(crate) r5: Univariate<F, 3>,
    // Bus column 2 (return_data)
    pub(crate) r6: Univariate<F, 5>,
    pub(crate) r7: Univariate<F, 5>,
    pub(crate) r8: Univariate<F, 3>,
}

impl<F: PrimeField> DatabusLookupRelationAcc<F> {
    pub(crate) fn scale(&mut self, elements: &[F]) {
        assert!(elements.len() == DatabusLookupRelation::NUM_RELATIONS);
        self.r0 *= elements[0];
        self.r1 *= elements[1];
        self.r2 *= elements[2];
        self.r3 *= elements[3];
        self.r4 *= elements[4];
        self.r5 *= elements[5];
        self.r6 *= elements[6];
        self.r7 *= elements[7];
        self.r8 *= elements[8];
    }

    pub(crate) fn extend_and_batch_univariates<const SIZE: usize>(
        &self,
        result: &mut Univariate<F, SIZE>,
        extended_random_poly: &Univariate<F, SIZE>,
        partial_evaluation_result: &F,
    ) {
        // inverse (independent), lookup (dependent), boolean (independent) per column
        self.r0.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r1.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, false);
        self.r2.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r3.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r4.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, false);
        self.r5.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r6.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
        self.r7.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, false);
        self.r8.extend_and_batch_univariates(result, extended_random_poly, partial_evaluation_result, true);
    }
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DatabusLookupRelationEvals<F: PrimeField> {
    pub(crate) r0: F, pub(crate) r1: F, pub(crate) r2: F,
    pub(crate) r3: F, pub(crate) r4: F, pub(crate) r5: F,
    pub(crate) r6: F, pub(crate) r7: F, pub(crate) r8: F,
}

impl<F: PrimeField> DatabusLookupRelationEvals<F> {
    pub(crate) fn scale_and_batch_elements(&self, running_challenge: &[F], result: &mut F) {
        assert!(running_challenge.len() == DatabusLookupRelation::NUM_RELATIONS);
        *result += self.r0 * running_challenge[0];
        *result += self.r1 * running_challenge[1];
        *result += self.r2 * running_challenge[2];
        *result += self.r3 * running_challenge[3];
        *result += self.r4 * running_challenge[4];
        *result += self.r5 * running_challenge[5];
        *result += self.r6 * running_challenge[6];
        *result += self.r7 * running_challenge[7];
        *result += self.r8 * running_challenge[8];
    }
}

pub(crate) struct DatabusLookupRelation {}

impl DatabusLookupRelation {
    pub(crate) const NUM_RELATIONS: usize = 9;

    /// Accumulate 3 subrelations for one bus column (prover side).
    ///
    /// Results are computed as full-size Univariates and truncated into the
    /// smaller accumulators element-by-element (same pattern as LogDerivLookup).
    fn accumulate_bus_column<F: PrimeField>(
        acc_inv: &mut Univariate<F, 5>,
        acc_lookup: &mut Univariate<F, 5>,
        acc_bool: &mut Univariate<F, 3>,
        bus_value: &Uni<F>,
        column_selector: &Uni<F>,
        bus_inverses: &Uni<F>,
        bus_read_counts: &Uni<F>,
        bus_read_tags: &Uni<F>,
        w_l: &Uni<F>,
        w_r: &Uni<F>,
        databus_id: &Uni<F>,
        q_busread: &Uni<F>,
        beta: &F,
        gamma: &F,
        scaling_factor: &F,
    ) {
        // lookup_term = w_r * beta + w_l + gamma  (degree 1)
        let lookup_term = w_r.to_owned() * beta + w_l + gamma;
        // table_term = databus_id * beta + bus_value + gamma  (degree 1)
        let table_term = databus_id.to_owned() * beta + bus_value + gamma;
        // read_selector = q_busread * column_selector  (degree 2)
        let read_selector = q_busread.to_owned() * column_selector;
        // inverse_exists = read_selector + read_tag - read_selector * read_tag  (degree 3)
        let inv_exists = read_selector.to_owned() + bus_read_tags
            - read_selector.to_owned() * bus_read_tags;

        // Subrelation 1: (lookup_term * table_term * inverses - inverse_exists) * scaling
        let tmp = (lookup_term.to_owned() * &table_term * bus_inverses - inv_exists) * scaling_factor;
        for i in 0..acc_inv.evaluations.len() {
            acc_inv.evaluations[i] += tmp.evaluations[i];
        }

        // Subrelation 2: (read_selector * table_term - read_count * lookup_term) * inverses
        let tmp = (read_selector * &table_term - bus_read_counts.to_owned() * &lookup_term)
            * bus_inverses;
        for i in 0..acc_lookup.evaluations.len() {
            acc_lookup.evaluations[i] += tmp.evaluations[i];
        }

        // Subrelation 3: (read_tag * read_tag - read_tag) * scaling
        let tmp = (bus_read_tags.to_owned() * bus_read_tags - bus_read_tags) * scaling_factor;
        for i in 0..acc_bool.evaluations.len() {
            acc_bool.evaluations[i] += tmp.evaluations[i];
        }
    }
}

impl<F: PrimeField> Relation<F> for DatabusLookupRelation {
    type Acc = DatabusLookupRelationAcc<F>;
    type VerifyAcc = DatabusLookupRelationEvals<F>;

    const SKIPPABLE: bool = true;

    fn skip(input: &ProverUnivariates<F>) -> bool {
        input.precomputed.q_busread().is_zero()
            && input.witness.calldata_read_counts().is_zero()
            && input.witness.secondary_calldata_read_counts().is_zero()
            && input.witness.return_data_read_counts().is_zero()
    }

    fn accumulate(
        univariate_accumulator: &mut Self::Acc,
        input: &ProverUnivariates<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        let w_l = input.witness.w_l();
        let w_r = input.witness.w_r();
        let databus_id = input.precomputed.databus_id();
        let q_busread = input.precomputed.q_busread();
        let beta = &relation_parameters.beta;
        let gamma = &relation_parameters.gamma;

        // Bus column 0: calldata (selected by q_busread * q_l)
        Self::accumulate_bus_column(
            &mut univariate_accumulator.r0,
            &mut univariate_accumulator.r1,
            &mut univariate_accumulator.r2,
            input.witness.calldata(),
            input.precomputed.q_l(),
            input.witness.calldata_inverses(),
            input.witness.calldata_read_counts(),
            input.witness.calldata_read_tags(),
            w_l, w_r, databus_id, q_busread, beta, gamma, scaling_factor,
        );

        // Bus column 1: secondary_calldata (selected by q_busread * q_r)
        Self::accumulate_bus_column(
            &mut univariate_accumulator.r3,
            &mut univariate_accumulator.r4,
            &mut univariate_accumulator.r5,
            input.witness.secondary_calldata(),
            input.precomputed.q_r(),
            input.witness.secondary_calldata_inverses(),
            input.witness.secondary_calldata_read_counts(),
            input.witness.secondary_calldata_read_tags(),
            w_l, w_r, databus_id, q_busread, beta, gamma, scaling_factor,
        );

        // Bus column 2: return_data (selected by q_busread * q_o)
        Self::accumulate_bus_column(
            &mut univariate_accumulator.r6,
            &mut univariate_accumulator.r7,
            &mut univariate_accumulator.r8,
            input.witness.return_data(),
            input.precomputed.q_o(),
            input.witness.return_data_inverses(),
            input.witness.return_data_read_counts(),
            input.witness.return_data_read_tags(),
            w_l, w_r, databus_id, q_busread, beta, gamma, scaling_factor,
        );
    }

    fn verify_accumulate(
        univariate_accumulator: &mut Self::VerifyAcc,
        input: &ClaimedEvaluations<F>,
        relation_parameters: &RelationParameters<F>,
        scaling_factor: &F,
    ) {
        let beta = relation_parameters.beta;
        let gamma = relation_parameters.gamma;
        let w_l = *input.witness.w_l();
        let w_r = *input.witness.w_r();
        let databus_id = *input.precomputed.databus_id();
        let q_busread = *input.precomputed.q_busread();

        let lookup_term = w_r * beta + w_l + gamma;

        let mut accum_column = |acc_inv: &mut F, acc_lookup: &mut F, acc_bool: &mut F,
                                 value: F, col_sel: F, inverses: F, read_counts: F, read_tags: F| {
            let table_term = databus_id * beta + value + gamma;
            let read_selector = q_busread * col_sel;
            let inverse_exists = read_selector + read_tags - read_selector * read_tags;

            *acc_inv += (lookup_term * table_term * inverses - inverse_exists) * *scaling_factor;
            *acc_lookup += (read_selector * table_term - read_counts * lookup_term) * inverses;
            *acc_bool += (read_tags * read_tags - read_tags) * *scaling_factor;
        };

        accum_column(
            &mut univariate_accumulator.r0, &mut univariate_accumulator.r1, &mut univariate_accumulator.r2,
            *input.witness.calldata(), *input.precomputed.q_l(),
            *input.witness.calldata_inverses(), *input.witness.calldata_read_counts(), *input.witness.calldata_read_tags(),
        );
        accum_column(
            &mut univariate_accumulator.r3, &mut univariate_accumulator.r4, &mut univariate_accumulator.r5,
            *input.witness.secondary_calldata(), *input.precomputed.q_r(),
            *input.witness.secondary_calldata_inverses(), *input.witness.secondary_calldata_read_counts(), *input.witness.secondary_calldata_read_tags(),
        );
        accum_column(
            &mut univariate_accumulator.r6, &mut univariate_accumulator.r7, &mut univariate_accumulator.r8,
            *input.witness.return_data(), *input.precomputed.q_o(),
            *input.witness.return_data_inverses(), *input.witness.return_data_read_counts(), *input.witness.return_data_read_tags(),
        );
    }
}
