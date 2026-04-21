use ark_ec::CurveGroup;
use ark_ff::{PrimeField, Zero};
use co_noir_common::polynomials::polynomial::Polynomial;
use co_noir_common::polynomials::shared_polynomial::SharedPolynomial;

use co_noir_common::mpc::NoirUltraHonkProver;
use ultrahonk::NUM_ALPHAS;
pub struct ProverMemory<T: NoirUltraHonkProver<P>, P: CurveGroup> {
    pub(crate) w_4: Polynomial<T::ArithmeticShare>, // column 3
    pub(crate) z_perm: Polynomial<T::ArithmeticShare>, // column 4
    pub(crate) lookup_inverses: Polynomial<T::ArithmeticShare>, // column 5
    pub(crate) public_input_delta: P::ScalarField,
    pub(crate) challenges: Challenges<P::ScalarField>,
    /// ZK: Gemini masking polynomial committed in oink, used in shplemini
    pub(crate) masking_poly: Option<SharedPolynomial<T, P>>,
}

pub(crate) struct Challenges<F: PrimeField> {
    pub(crate) eta_1: F,
    pub(crate) eta_2: F,
    pub(crate) eta_3: F,
    pub(crate) beta: F,
    pub(crate) beta_sqr: F,
    pub(crate) beta_cube: F,
    pub(crate) gamma: F,
    pub(crate) alphas: [F; NUM_ALPHAS],
}

impl<F: PrimeField> Default for Challenges<F> {
    fn default() -> Self {
        Self {
            eta_1: Default::default(),
            eta_2: Default::default(),
            eta_3: Default::default(),
            beta: Default::default(),
            beta_sqr: Default::default(),
            beta_cube: Default::default(),
            gamma: Default::default(),
            alphas: [F::zero(); NUM_ALPHAS],
        }
    }
}

impl<T: NoirUltraHonkProver<P>, P: CurveGroup> Default for ProverMemory<T, P> {
    fn default() -> Self {
        Self {
            w_4: Default::default(),
            z_perm: Default::default(),
            lookup_inverses: Default::default(),
            public_input_delta: Default::default(),
            challenges: Default::default(),
            masking_poly: None,
        }
    }
}
