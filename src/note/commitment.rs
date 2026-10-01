//! Note commitments and their trapdoors.
//!
//! A [`NoteCommitment`] is the Sinsemilla commitment to the contents of a
//! note, binding the diversified transmission key, note value, ρ, and ψ. Its
//! x-coordinate is exposed as [`ExtractedNoteCommitment`] (the value
//! appearing in the commitment tree), and its randomness is
//! [`NoteCommitTrapdoor`].

use core::iter;

use bitvec::{array::BitArray, order::Lsb0};
use group::ff::{PrimeField, PrimeFieldBits};
use lazy_static::lazy_static;
use pasta_curves::pallas;
use subtle::{ConstantTimeEq, CtOption};

use crate::{
    constants::{fixed_bases::NOTE_COMMITMENT_PERSONALIZATION, L_ORCHARD_BASE},
    spec::extract_p,
    value::NoteValue,
};

lazy_static! {
    static ref NOTE_COMMITMENT_DOMAIN: sinsemilla::CommitDomain =
        sinsemilla::CommitDomain::new(NOTE_COMMITMENT_PERSONALIZATION);
}

fn note_commitment_domain() -> &'static sinsemilla::CommitDomain {
    &NOTE_COMMITMENT_DOMAIN
}

/// The trapdoor for a note commitment.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "unstable-voting-circuits", visibility::make(pub))]
#[cfg_attr(feature = "unsafe-zns", visibility::make(pub))]
pub(crate) struct NoteCommitTrapdoor(pub(super) pallas::Scalar);

impl NoteCommitTrapdoor {
    /// Returns the inner scalar value.
    #[cfg_attr(feature = "unstable-voting-circuits", visibility::make(pub))]
    #[cfg_attr(feature = "unsafe-zns", visibility::make(pub))]
    pub(crate) fn inner(&self) -> pallas::Scalar {
        self.0
    }

    /// Wraps a caller-supplied scalar as a commitment trapdoor (ZcashName).
    #[cfg(feature = "unsafe-zns")]
    pub fn from_inner(inner: pallas::Scalar) -> Self {
        NoteCommitTrapdoor(inner)
    }

    /// Deserialize from bytes (ZcashName).
    #[cfg(feature = "unsafe-zns")]
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Scalar::from_repr(*bytes).map(NoteCommitTrapdoor)
    }

    /// Serialize to canonical byte representation (ZcashName).
    #[cfg(feature = "unsafe-zns")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[cfg(feature = "unsafe-zns")]
impl ConstantTimeEq for NoteCommitTrapdoor {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(feature = "unsafe-zns")]
impl PartialEq for NoteCommitTrapdoor {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "unsafe-zns")]
impl Eq for NoteCommitTrapdoor {}

/// ψ_σ: the ZNS note-commitment input (whitepaper §3.3).
///
/// A Name Note's note commitment is derived from the pair `(rcm_σ, ψ_σ)` —
/// both reduced from the same encoded transition by tagged BLAKE2b — instead
/// of the values derived from the note's `rseed`. This is the counterpart of
/// [`NoteCommitTrapdoor`] on the base-field side.
#[derive(Clone, Copy, Debug)]
#[cfg_attr(feature = "unsafe-zns", visibility::make(pub))]
pub(crate) struct Psi(pub(super) pallas::Base);

impl Psi {
    /// Returns the inner base field element.
    #[cfg_attr(feature = "unsafe-zns", visibility::make(pub))]
    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }

    /// Wraps a caller-supplied base field element as ψ (ZcashName).
    #[cfg_attr(feature = "unsafe-zns", visibility::make(pub))]
    pub(crate) fn from_inner(inner: pallas::Base) -> Self {
        Psi(inner)
    }

    /// Deserialize from bytes (ZcashName).
    #[cfg(feature = "unsafe-zns")]
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(Psi)
    }

    /// Serialize to canonical byte representation (ZcashName).
    #[cfg(feature = "unsafe-zns")]
    pub fn to_bytes(&self) -> [u8; 32] {
        self.0.to_repr()
    }
}

#[cfg(feature = "unsafe-zns")]
impl ConstantTimeEq for Psi {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

#[cfg(feature = "unsafe-zns")]
impl PartialEq for Psi {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

#[cfg(feature = "unsafe-zns")]
impl Eq for Psi {}

/// A commitment to a note.
#[derive(Clone, Debug)]
pub struct NoteCommitment(pub(super) pallas::Point);

impl NoteCommitment {
    /// Returns the inner Pallas curve point.
    #[cfg_attr(feature = "unstable-voting-circuits", visibility::make(pub))]
    pub(crate) fn inner(&self) -> pallas::Point {
        self.0
    }
}

impl NoteCommitment {
    /// $NoteCommit^Orchard$.
    ///
    /// Defined in [Zcash Protocol Spec § 5.4.8.4: Sinsemilla commitments][concretesinsemillacommit].
    ///
    /// [concretesinsemillacommit]: https://zips.z.cash/protocol/nu5.pdf#concretesinsemillacommit
    pub(crate) fn derive(
        g_d: [u8; 32],
        pk_d: [u8; 32],
        v: NoteValue,
        rho: pallas::Base,
        psi: pallas::Base,
        rcm: NoteCommitTrapdoor,
    ) -> CtOption<Self> {
        let domain = note_commitment_domain();
        domain
            .commit(
                iter::empty()
                    .chain(BitArray::<_, Lsb0>::new(g_d).iter().by_vals())
                    .chain(BitArray::<_, Lsb0>::new(pk_d).iter().by_vals())
                    .chain(v.to_le_bits().iter().by_vals())
                    .chain(rho.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE))
                    .chain(psi.to_le_bits().iter().by_vals().take(L_ORCHARD_BASE)),
                &rcm.0,
            )
            .map(NoteCommitment)
    }
}

/// The x-coordinate of the commitment to a note.
#[derive(Copy, Clone, Debug)]
pub struct ExtractedNoteCommitment(pub(super) pallas::Base);

impl ExtractedNoteCommitment {
    /// Deserialize the extracted note commitment from a byte array.
    ///
    /// This method enforces the [consensus rule][cmxcanon] that the
    /// byte representation of cmx MUST be canonical.
    ///
    /// [cmxcanon]: https://zips.z.cash/protocol/protocol.pdf#actionencodingandconsensus
    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Self> {
        pallas::Base::from_repr(*bytes).map(ExtractedNoteCommitment)
    }

    /// Serialize the value commitment to its canonical byte representation.
    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_repr()
    }
}

impl From<NoteCommitment> for ExtractedNoteCommitment {
    fn from(cm: NoteCommitment) -> Self {
        ExtractedNoteCommitment(extract_p(&cm.0))
    }
}

impl ExtractedNoteCommitment {
    /// Returns the inner field element.
    #[cfg_attr(feature = "unstable-voting-circuits", visibility::make(pub))]
    pub(crate) fn inner(&self) -> pallas::Base {
        self.0
    }
}

impl From<&ExtractedNoteCommitment> for [u8; 32] {
    fn from(cmx: &ExtractedNoteCommitment) -> Self {
        cmx.to_bytes()
    }
}

/// Strategies for generating ZNS commitment inputs.
#[cfg(all(feature = "unsafe-zns", any(test, feature = "test-dependencies")))]
pub mod testing {
    /// `FromUniformBytes` input width required by the Pasta field implementations.
    const UNIFORM_BYTES_LEN: usize = 64;

    use group::ff::FromUniformBytes;
    use pasta_curves::pallas;
    use proptest::prelude::*;

    use super::{NoteCommitTrapdoor, Psi};

    /// Generates an arbitrary `Psi` from uniformly random bytes.
    pub fn arb_psi() -> impl Strategy<Value = Psi> {
        proptest::collection::vec(any::<u8>(), UNIFORM_BYTES_LEN).prop_map(|v| {
            let mut bytes = [0u8; UNIFORM_BYTES_LEN];
            bytes.copy_from_slice(&v);
            Psi::from_inner(pallas::Base::from_uniform_bytes(&bytes))
        })
    }

    /// Generates an arbitrary `NoteCommitTrapdoor` from uniformly random bytes.
    pub fn arb_note_commit_trapdoor() -> impl Strategy<Value = NoteCommitTrapdoor> {
        proptest::collection::vec(any::<u8>(), UNIFORM_BYTES_LEN).prop_map(|v| {
            let mut bytes = [0u8; UNIFORM_BYTES_LEN];
            bytes.copy_from_slice(&v);
            NoteCommitTrapdoor::from_inner(pallas::Scalar::from_uniform_bytes(&bytes))
        })
    }
}

impl ConstantTimeEq for ExtractedNoteCommitment {
    fn ct_eq(&self, other: &Self) -> subtle::Choice {
        self.0.ct_eq(&other.0)
    }
}

impl PartialEq for ExtractedNoteCommitment {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

impl Eq for ExtractedNoteCommitment {}
