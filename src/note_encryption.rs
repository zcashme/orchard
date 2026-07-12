//! In-band secret distribution for Orchard bundles.

use alloc::vec::Vec;
use core::fmt;

use blake2b_simd::{Hash, Params};
use group::ff::PrimeField;
use zcash_note_encryption::{
    BatchDomain, Domain, EphemeralKeyBytes, NotePlaintextBytes, OutPlaintextBytes,
    OutgoingCipherKey, ShieldedOutput, COMPACT_NOTE_SIZE, ENC_CIPHERTEXT_SIZE, NOTE_PLAINTEXT_SIZE,
    OUT_PLAINTEXT_SIZE,
};

use crate::{
    action::Action,
    keys::{
        DiversifiedTransmissionKey, Diversifier, EphemeralPublicKey, EphemeralSecretKey,
        OutgoingViewingKey, PreparedEphemeralPublicKey, PreparedIncomingViewingKey, SharedSecret,
    },
    note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
    value::{NoteValue, ValueCommitment},
    Address, Note,
};

const PRF_OCK_ORCHARD_PERSONALIZATION: &[u8; 16] = b"Zcash_Orchardock";

/// Defined in [Zcash Protocol Spec § 5.4.2: Pseudo Random Functions][concreteprfs].
///
/// [concreteprfs]: https://zips.z.cash/protocol/nu5.pdf#concreteprfs
pub(crate) fn prf_ock_orchard(
    ovk: &OutgoingViewingKey,
    cv: &ValueCommitment,
    cmx_bytes: &[u8; 32],
    ephemeral_key: &EphemeralKeyBytes,
) -> OutgoingCipherKey {
    OutgoingCipherKey(
        Params::new()
            .hash_length(32)
            .personal(PRF_OCK_ORCHARD_PERSONALIZATION)
            .to_state()
            .update(ovk.as_ref())
            .update(&cv.to_bytes())
            .update(cmx_bytes)
            .update(ephemeral_key.as_ref())
            .finalize()
            .as_bytes()
            .try_into()
            .unwrap(),
    )
}

fn parse_note_plaintext_without_memo<F>(
    rho: Rho,
    plaintext: &[u8],
    note_version: NoteVersion,
    get_pk_d: F,
) -> Option<(Note, Address)>
where
    F: FnOnce(&Diversifier) -> DiversifiedTransmissionKey,
{
    assert!(plaintext.len() >= COMPACT_NOTE_SIZE);

    // The unwraps below are guaranteed to succeed by the assertion above
    let diversifier = Diversifier::from_bytes(plaintext[1..12].try_into().unwrap());
    let value = NoteValue::from_bytes(plaintext[12..20].try_into().unwrap());
    let rseed = Option::from(RandomSeed::from_bytes(
        plaintext[20..COMPACT_NOTE_SIZE].try_into().unwrap(),
        &rho,
    ))?;

    let pk_d = get_pk_d(&diversifier);

    let recipient = Address::from_parts(diversifier, pk_d);
    let note = Option::from(Note::from_parts(recipient, value, rho, rseed, note_version))?;
    Some((note, recipient))
}

mod sealed {
    /// Marker trait that prevents external `DomainVersion` implementations.
    pub trait Sealed {}
}

trait DomainPolicy {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion>;
}

/// A sealed marker trait for note encryption domains with a fixed note plaintext version.
///
/// This trait is sealed so that only this crate can define supported note encryption
/// domains.
pub trait DomainVersion: sealed::Sealed + Default {
    /// The note plaintext version accepted by this domain during parsing and decryption.
    const NOTE_VERSION: NoteVersion;
}

impl<V: DomainVersion> DomainPolicy for V {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion> {
        if plaintext.first().copied() == Some(V::NOTE_VERSION.lead_byte()) {
            Some(V::NOTE_VERSION)
        } else {
            None
        }
    }
}

/// Marker type for Orchard note encryption domains.
#[derive(Default, Debug)]
pub struct OrchardVersion;

impl sealed::Sealed for OrchardVersion {}

impl DomainVersion for OrchardVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V2;
}

/// Marker type for Ironwood note encryption domains.
#[derive(Default, Debug)]
pub struct IronwoodVersion;

impl sealed::Sealed for IronwoodVersion {}

impl DomainVersion for IronwoodVersion {
    const NOTE_VERSION: NoteVersion = NoteVersion::V3;
}

#[derive(Debug)]
pub(crate) struct BundleDomainPolicy {
    note_version: NoteVersion,
}

impl DomainPolicy for BundleDomainPolicy {
    fn note_version(&self, plaintext: &[u8]) -> Option<NoteVersion> {
        let note_version = NoteVersion::from_lead_byte(*plaintext.first()?)?;
        if note_version == self.note_version {
            Some(note_version)
        } else {
            None
        }
    }
}

/// Note encryption logic for a note plaintext version policy.
///
/// The policy type `P` selects which note plaintext version is accepted during
/// parsing and decryption. Encryption uses the version recorded by the note.
#[derive(Debug)]
pub struct NoteEncryptionDomain<P> {
    rho: Rho,
    policy: P,
}

impl<P> memuse::DynamicUsage for NoteEncryptionDomain<P> {
    fn dynamic_usage(&self) -> usize {
        self.rho.dynamic_usage()
    }

    fn dynamic_usage_bounds(&self) -> (usize, Option<usize>) {
        self.rho.dynamic_usage_bounds()
    }
}

impl<V: DomainVersion> NoteEncryptionDomain<V> {
    pub(crate) fn from_rho(rho: Rho) -> Self {
        Self {
            rho,
            policy: V::default(),
        }
    }

    /// Constructs a domain that can be used to trial-decrypt this action's output note.
    pub fn for_action<T>(act: &Action<T>) -> Self {
        Self::from_rho(act.rho())
    }

    /// Constructs a domain that can be used to trial-decrypt a PCZT action's output note.
    pub fn for_pczt_action(act: &crate::pczt::Action) -> Self {
        Self::from_rho(Rho::from_nf_old(act.spend().nullifier))
    }

    /// Constructs a domain that can be used to trial-decrypt this compact action's output note.
    pub fn for_compact_action(act: &CompactAction) -> Self {
        Self::from_rho(act.rho())
    }
}

/// Orchard-specific note encryption logic.
///
/// This domain accepts only [`NoteVersion::V2`] note plaintexts, which use lead
/// byte `0x02`.
pub type OrchardDomain = NoteEncryptionDomain<OrchardVersion>;

/// Ironwood-specific note encryption logic.
///
/// This domain is otherwise identical to [`OrchardDomain`], but accepts only
/// [`NoteVersion::V3`] note plaintexts, which use lead byte `0x03`.
pub type IronwoodDomain = NoteEncryptionDomain<IronwoodVersion>;

/// Trial-decryption domain for ZcashName Name Notes in the Ironwood pool.
///
/// Name Notes use the Ironwood V3 note plaintext format, but their note
/// commitment is derived from ZcashName data in the encrypted memo rather
/// than from the plaintext's `rseed`. [`ZnsIronwoodDomain::try_decrypt`]
/// therefore requires a validator that checks the ZcashName commitment before
/// returning the decrypted note.
///
/// This domain is limited to Ironwood because the `unsafe-zns` builder surface
/// creates Name Notes only in Ironwood V3 bundles.
#[cfg(feature = "unsafe-zns")]
#[derive(Debug)]
pub struct ZnsIronwoodDomain {
    rho: Rho,
    cmx: ExtractedNoteCommitment,
}

#[cfg(feature = "unsafe-zns")]
struct ZnsCandidateNote {
    note: Note,
    cmx: ExtractedNoteCommitment,
}

#[cfg(feature = "unsafe-zns")]
impl ZnsIronwoodDomain {
    /// Constructs the ZcashName trial-decryption domain for an Ironwood action.
    pub fn for_action<T>(action: &Action<T>) -> Self {
        Self {
            rho: action.rho(),
            cmx: *action.cmx(),
        }
    }

    /// Decrypts an Ironwood Name Note and validates its ZcashName commitment.
    ///
    /// The supplied validator receives the authenticated note plaintext, its
    /// memo, and the action commitment. It must derive the ZcashName opening
    /// from the memo and check it against `cmx`. If it rejects the opening,
    /// this method returns `None` and the plaintext is not exposed.
    ///
    /// The generic in-band decryption path still authenticates the ciphertext
    /// and verifies the `rseed`-derived ephemeral key against the action's
    /// `epk`; only the standard `rseed`-derived `cmx` rule is replaced.
    pub fn try_decrypt<T, F>(
        &self,
        action: &Action<T>,
        ivk: &PreparedIncomingViewingKey,
        validate: F,
    ) -> Option<(Note, Address, [u8; 512])>
    where
        F: FnOnce(&Note, &[u8; 512], &ExtractedNoteCommitment) -> subtle::Choice,
    {
        let (candidate, recipient, memo) =
            zcash_note_encryption::try_note_decryption(self, ivk, action)?;

        if bool::from(validate(&candidate.note, &memo, &candidate.cmx)) {
            Some((candidate.note, recipient, memo))
        } else {
            None
        }
    }
}

/// Note encryption logic restricted to a single note plaintext version.
///
/// This domain is used by public bundle helpers that are given the bundle's
/// [`NoteVersion`]. Trial decryption still happens once; after decryption
/// succeeds, the revealed note plaintext lead byte selects the note version, which is
/// enforced to match the expected one.
pub(crate) type BundleDomain = NoteEncryptionDomain<BundleDomainPolicy>;

impl BundleDomain {
    /// Constructs a domain that can be used to trial-decrypt this action's
    /// output note as a note of `note_version`.
    pub(crate) fn for_action<T>(act: &Action<T>, note_version: NoteVersion) -> Self {
        Self {
            rho: act.rho(),
            policy: BundleDomainPolicy { note_version },
        }
    }
}

impl<P: DomainPolicy> Domain for NoteEncryptionDomain<P> {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Hash;
    type Note = Note;
    type Recipient = Address;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; 512]; // TODO use a more interesting type

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.esk())
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey::new(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        esk.derive_public(note.recipient().g_d())
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        esk.agree(pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk.agree(ivk)
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        secret.kdf_orchard(ephemeral_key)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        let mut np = [0; NOTE_PLAINTEXT_SIZE];
        np[0] = note.version().lead_byte();
        np[1..12].copy_from_slice(note.recipient().diversifier().as_array());
        np[12..20].copy_from_slice(&note.value().to_bytes());
        np[20..52].copy_from_slice(note.rseed().as_bytes());
        np[52..].copy_from_slice(memo);
        NotePlaintextBytes(np)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock_orchard(ovk, cv, cmstar_bytes, ephemeral_key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        let mut op = [0; OUT_PLAINTEXT_SIZE];
        op[..32].copy_from_slice(&note.recipient().pk_d().to_bytes());
        op[32..].copy_from_slice(&esk.0.to_repr());
        OutPlaintextBytes(op)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk.to_bytes()
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.commitment().into()
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        let note_version = self.policy.note_version(plaintext)?;
        parse_note_plaintext_without_memo(self.rho, plaintext, note_version, |diversifier| {
            DiversifiedTransmissionKey::derive(ivk, diversifier)
        })
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &NotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let note_version = self.policy.note_version(&plaintext.0)?;
        parse_note_plaintext_without_memo(self.rho, &plaintext.0, note_version, |_| *pk_d)
    }

    fn extract_memo(&self, plaintext: &NotePlaintextBytes) -> Self::Memo {
        plaintext.0[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]
            .try_into()
            .unwrap()
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
            .into()
    }
}

#[cfg(feature = "unsafe-zns")]
impl Domain for ZnsIronwoodDomain {
    type EphemeralSecretKey = EphemeralSecretKey;
    type EphemeralPublicKey = EphemeralPublicKey;
    type PreparedEphemeralPublicKey = PreparedEphemeralPublicKey;
    type SharedSecret = SharedSecret;
    type SymmetricKey = Hash;
    type Note = ZnsCandidateNote;
    type Recipient = Address;
    type DiversifiedTransmissionKey = DiversifiedTransmissionKey;
    type IncomingViewingKey = PreparedIncomingViewingKey;
    type OutgoingViewingKey = OutgoingViewingKey;
    type ValueCommitment = ValueCommitment;
    type ExtractedCommitment = ExtractedNoteCommitment;
    type ExtractedCommitmentBytes = [u8; 32];
    type Memo = [u8; 512];

    fn derive_esk(note: &Self::Note) -> Option<Self::EphemeralSecretKey> {
        Some(note.note.esk())
    }

    fn get_pk_d(note: &Self::Note) -> Self::DiversifiedTransmissionKey {
        *note.note.recipient().pk_d()
    }

    fn prepare_epk(epk: Self::EphemeralPublicKey) -> Self::PreparedEphemeralPublicKey {
        PreparedEphemeralPublicKey::new(epk)
    }

    fn ka_derive_public(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> Self::EphemeralPublicKey {
        esk.derive_public(note.note.recipient().g_d())
    }

    fn ka_agree_enc(
        esk: &Self::EphemeralSecretKey,
        pk_d: &Self::DiversifiedTransmissionKey,
    ) -> Self::SharedSecret {
        esk.agree(pk_d)
    }

    fn ka_agree_dec(
        ivk: &Self::IncomingViewingKey,
        epk: &Self::PreparedEphemeralPublicKey,
    ) -> Self::SharedSecret {
        epk.agree(ivk)
    }

    fn kdf(secret: Self::SharedSecret, ephemeral_key: &EphemeralKeyBytes) -> Self::SymmetricKey {
        secret.kdf_orchard(ephemeral_key)
    }

    fn note_plaintext_bytes(note: &Self::Note, memo: &Self::Memo) -> NotePlaintextBytes {
        NoteEncryptionDomain::<IronwoodVersion>::note_plaintext_bytes(&note.note, memo)
    }

    fn derive_ock(
        ovk: &Self::OutgoingViewingKey,
        cv: &Self::ValueCommitment,
        cmstar_bytes: &Self::ExtractedCommitmentBytes,
        ephemeral_key: &EphemeralKeyBytes,
    ) -> OutgoingCipherKey {
        prf_ock_orchard(ovk, cv, cmstar_bytes, ephemeral_key)
    }

    fn outgoing_plaintext_bytes(
        note: &Self::Note,
        esk: &Self::EphemeralSecretKey,
    ) -> OutPlaintextBytes {
        NoteEncryptionDomain::<IronwoodVersion>::outgoing_plaintext_bytes(&note.note, esk)
    }

    fn epk_bytes(epk: &Self::EphemeralPublicKey) -> EphemeralKeyBytes {
        epk.to_bytes()
    }

    fn epk(ephemeral_key: &EphemeralKeyBytes) -> Option<Self::EphemeralPublicKey> {
        EphemeralPublicKey::from_bytes(&ephemeral_key.0).into()
    }

    fn cmstar(note: &Self::Note) -> Self::ExtractedCommitment {
        note.cmx
    }

    fn parse_note_plaintext_without_memo_ivk(
        &self,
        ivk: &Self::IncomingViewingKey,
        plaintext: &[u8],
    ) -> Option<(Self::Note, Self::Recipient)> {
        let (note, recipient) = parse_note_plaintext_without_memo(
            self.rho,
            plaintext,
            NoteVersion::V3,
            |diversifier| DiversifiedTransmissionKey::derive(ivk, diversifier),
        )?;
        Some((
            ZnsCandidateNote {
                note,
                cmx: self.cmx,
            },
            recipient,
        ))
    }

    fn parse_note_plaintext_without_memo_ovk(
        &self,
        pk_d: &Self::DiversifiedTransmissionKey,
        plaintext: &NotePlaintextBytes,
    ) -> Option<(Self::Note, Self::Recipient)> {
        let (note, recipient) = parse_note_plaintext_without_memo(
            self.rho,
            &plaintext.0,
            NoteVersion::V3,
            |_| *pk_d,
        )?;
        Some((
            ZnsCandidateNote {
                note,
                cmx: self.cmx,
            },
            recipient,
        ))
    }

    fn extract_memo(&self, plaintext: &NotePlaintextBytes) -> Self::Memo {
        plaintext.0[COMPACT_NOTE_SIZE..NOTE_PLAINTEXT_SIZE]
            .try_into()
            .unwrap()
    }

    fn extract_pk_d(out_plaintext: &OutPlaintextBytes) -> Option<Self::DiversifiedTransmissionKey> {
        DiversifiedTransmissionKey::from_bytes(out_plaintext.0[0..32].try_into().unwrap()).into()
    }

    fn extract_esk(out_plaintext: &OutPlaintextBytes) -> Option<Self::EphemeralSecretKey> {
        EphemeralSecretKey::from_bytes(out_plaintext.0[32..OUT_PLAINTEXT_SIZE].try_into().unwrap())
            .into()
    }
}

impl<P: DomainPolicy> BatchDomain for NoteEncryptionDomain<P> {
    fn batch_kdf<'a>(
        items: impl Iterator<Item = (Option<Self::SharedSecret>, &'a EphemeralKeyBytes)>,
    ) -> Vec<Option<Self::SymmetricKey>> {
        batch_kdf(items)
    }
}

fn batch_kdf<'a>(
    items: impl Iterator<Item = (Option<SharedSecret>, &'a EphemeralKeyBytes)>,
) -> Vec<Option<Hash>> {
    let (shared_secrets, ephemeral_keys): (Vec<_>, Vec<_>) = items.unzip();

    SharedSecret::batch_to_affine(shared_secrets)
        .zip(ephemeral_keys)
        .map(|(secret, ephemeral_key)| {
            secret.map(|dhsecret| SharedSecret::kdf_orchard_inner(dhsecret, ephemeral_key))
        })
        .collect()
}

impl<P: DomainPolicy, T> ShieldedOutput<NoteEncryptionDomain<P>, ENC_CIPHERTEXT_SIZE>
    for Action<T>
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.encrypted_note().enc_ciphertext
    }
}

#[cfg(feature = "unsafe-zns")]
impl<T> ShieldedOutput<ZnsIronwoodDomain, ENC_CIPHERTEXT_SIZE> for Action<T> {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.encrypted_note().enc_ciphertext
    }
}

impl<P: DomainPolicy> ShieldedOutput<NoteEncryptionDomain<P>, ENC_CIPHERTEXT_SIZE>
    for crate::pczt::Action
{
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.output().encrypted_note().epk_bytes)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.output().cmx().to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; ENC_CIPHERTEXT_SIZE] {
        &self.output().encrypted_note().enc_ciphertext
    }
}

impl<P: DomainPolicy> ShieldedOutput<NoteEncryptionDomain<P>, COMPACT_NOTE_SIZE> for CompactAction {
    fn ephemeral_key(&self) -> EphemeralKeyBytes {
        EphemeralKeyBytes(self.ephemeral_key.0)
    }

    fn cmstar_bytes(&self) -> [u8; 32] {
        self.cmx.to_bytes()
    }

    fn enc_ciphertext(&self) -> &[u8; COMPACT_NOTE_SIZE] {
        &self.enc_ciphertext
    }
}

/// Implementation of in-band secret distribution for Orchard bundles.
///
/// This is the [`NoteEncryption`] instantiation for [`OrchardDomain`]. Encryption
/// behavior is shared with [`IronwoodNoteEncryption`]: the note plaintext lead
/// byte is selected from [`crate::Note::version`], while the domain type
/// controls which note plaintext versions are accepted during parsing and
/// decryption.
///
/// [`NoteEncryption`]: zcash_note_encryption::NoteEncryption
pub type OrchardNoteEncryption = zcash_note_encryption::NoteEncryption<OrchardDomain>;
/// Implementation of in-band secret distribution for Ironwood bundles.
///
/// This is the [`NoteEncryption`] instantiation for [`IronwoodDomain`]. Encryption
/// behavior is shared with [`OrchardNoteEncryption`]: the note plaintext lead
/// byte is selected from [`crate::Note::version`], while the domain type
/// controls which note plaintext versions are accepted during parsing and
/// decryption.
///
/// [`NoteEncryption`]: zcash_note_encryption::NoteEncryption
pub type IronwoodNoteEncryption = zcash_note_encryption::NoteEncryption<IronwoodDomain>;

/// A compact Action for light clients.
#[derive(Clone)]
pub struct CompactAction {
    nullifier: Nullifier,
    cmx: ExtractedNoteCommitment,
    ephemeral_key: EphemeralKeyBytes,
    enc_ciphertext: [u8; 52],
}

impl fmt::Debug for CompactAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CompactAction")
    }
}

impl<T> From<&Action<T>> for CompactAction {
    fn from(action: &Action<T>) -> Self {
        CompactAction {
            nullifier: *action.nullifier(),
            cmx: *action.cmx(),
            ephemeral_key: EphemeralKeyBytes(action.encrypted_note().epk_bytes),
            enc_ciphertext: action.encrypted_note().enc_ciphertext[..52]
                .try_into()
                .unwrap(),
        }
    }
}

impl CompactAction {
    /// Create a CompactAction from its constituent parts
    pub fn from_parts(
        nullifier: Nullifier,
        cmx: ExtractedNoteCommitment,
        ephemeral_key: EphemeralKeyBytes,
        enc_ciphertext: [u8; 52],
    ) -> Self {
        Self {
            nullifier,
            cmx,
            ephemeral_key,
            enc_ciphertext,
        }
    }

    /// Returns the nullifier of the note being spent.
    pub fn nullifier(&self) -> Nullifier {
        self.nullifier
    }

    /// Returns the commitment to the new note being created.
    pub fn cmx(&self) -> ExtractedNoteCommitment {
        self.cmx
    }

    /// Obtains the [`Rho`] value that was used to construct the new note being created.
    pub fn rho(&self) -> Rho {
        Rho::from_nf_old(self.nullifier)
    }
}

/// Utilities for constructing test data.
#[cfg(feature = "test-dependencies")]
pub mod testing {
    use rand::RngCore;
    use zcash_note_encryption::Domain;

    use crate::{
        keys::OutgoingViewingKey,
        note::{ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho},
        value::NoteValue,
        Address, Note,
    };

    use super::{CompactAction, OrchardDomain, OrchardNoteEncryption};

    /// Creates a fake `CompactAction` paying the given recipient the specified value.
    ///
    /// Returns the `CompactAction` and the new note.
    pub fn fake_compact_action<R: RngCore>(
        rng: &mut R,
        nf_old: Nullifier,
        recipient: Address,
        value: NoteValue,
        ovk: Option<OutgoingViewingKey>,
    ) -> (CompactAction, Note) {
        let rho = Rho::from_nf_old(nf_old);
        let rseed = {
            loop {
                let mut bytes = [0; 32];
                rng.fill_bytes(&mut bytes);
                let rseed = RandomSeed::from_bytes(bytes, &rho);
                if rseed.is_some().into() {
                    break rseed.unwrap();
                }
            }
        };
        let note = Note::from_parts(recipient, value, rho, rseed, NoteVersion::V2).unwrap();
        let encryptor = OrchardNoteEncryption::new(ovk, note, [0u8; 512]);
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let ephemeral_key = OrchardDomain::epk_bytes(encryptor.epk());
        let enc_ciphertext = encryptor.encrypt_note_plaintext();

        (
            CompactAction {
                nullifier: nf_old,
                cmx,
                ephemeral_key,
                enc_ciphertext: enc_ciphertext.as_ref()[..52].try_into().unwrap(),
            },
            note,
        )
    }
}

#[cfg(test)]
mod tests {
    use rand::rngs::OsRng;
    use zcash_note_encryption::{
        try_compact_note_decryption, try_note_decryption, try_output_recovery_with_ovk, Domain,
        EphemeralKeyBytes,
    };

    use super::{
        prf_ock_orchard, CompactAction, IronwoodDomain, IronwoodNoteEncryption, OrchardDomain,
        OrchardNoteEncryption,
    };
    #[cfg(feature = "unsafe-zns")]
    use super::ZnsIronwoodDomain;
    use crate::{
        action::Action,
        keys::{
            DiversifiedTransmissionKey, Diversifier, EphemeralSecretKey, IncomingViewingKey,
            OutgoingViewingKey, PreparedIncomingViewingKey, Scope, SpendingKey,
        },
        note::{
            ExtractedNoteCommitment, NoteVersion, Nullifier, RandomSeed, Rho,
            TransmittedNoteCiphertext,
        },
        primitives::redpallas,
        value::{NoteValue, ValueCommitTrapdoor, ValueCommitment, ValueSum},
        Address, Note,
    };

    fn v3_encrypted_action() -> (
        Action<()>,
        PreparedIncomingViewingKey,
        Note,
        Address,
        [u8; 512],
    ) {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let incoming_viewing_key = fvk.to_ivk(Scope::External);
        let prepared_ivk = PreparedIncomingViewingKey::new(&incoming_viewing_key);
        let recipient = fvk.address_at(0u32, Scope::External);
        let nf_old = Nullifier::dummy(&mut rng);
        let rho = Rho::from_nf_old(nf_old);
        let note = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let memo = [7u8; 512];
        let cv_net = ValueCommitment::derive(ValueSum::from_raw(5), ValueCommitTrapdoor::zero());
        let cmx = ExtractedNoteCommitment::from(note.commitment());
        let encryptor = IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, memo);
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
        };
        let action = Action::from_parts(
            nf_old,
            redpallas::VerificationKey::dummy(),
            cmx,
            encrypted_note,
            cv_net,
            (),
        )
        .expect("a dummy verification key is unlikely to be the identity");

        (action, prepared_ivk, note, recipient, memo)
    }

    #[cfg(feature = "unsafe-zns")]
    fn v3_nonstandard_commitment_action() -> (
        Action<()>,
        PreparedIncomingViewingKey,
        Note,
        Address,
        [u8; 512],
    ) {
        let mut rng = OsRng;
        let sk = SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let incoming_viewing_key = fvk.to_ivk(Scope::External);
        let prepared_ivk = PreparedIncomingViewingKey::new(&incoming_viewing_key);
        let recipient = fvk.address_at(0u32, Scope::External);
        let nf_old = Nullifier::dummy(&mut rng);
        let rho = Rho::from_nf_old(nf_old);
        let note = Note::new(
            recipient,
            NoteValue::ZERO,
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let memo = [7u8; 512];
        // A Name Note's action cmx is not derived from the encrypted note's
        // rseed. A second note gives this test the same structural mismatch
        // without making ZNS commitment derivation part of the Orchard API.
        let cmx = ExtractedNoteCommitment::from(
            Note::new(
                recipient,
                NoteValue::ZERO,
                rho,
                NoteVersion::V3,
                &mut rng,
            )
            .commitment(),
        );
        let cv_net =
            ValueCommitment::derive(ValueSum::from_raw(0), ValueCommitTrapdoor::zero());
        let encryptor =
            IronwoodNoteEncryption::new(Some(fvk.to_ovk(Scope::External)), note, memo);
        let encrypted_note = TransmittedNoteCiphertext {
            epk_bytes: IronwoodDomain::epk_bytes(encryptor.epk()).0,
            enc_ciphertext: encryptor.encrypt_note_plaintext(),
            out_ciphertext: encryptor.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut rng),
        };
        let action = Action::from_parts(
            nf_old,
            redpallas::VerificationKey::dummy(),
            cmx,
            encrypted_note,
            cv_net,
            (),
        )
        .expect("a dummy verification key is unlikely to be the identity");

        (action, prepared_ivk, note, recipient, memo)
    }

    #[test]
    fn test_vectors() {
        let test_vectors = crate::test_vectors::note_encryption::test_vectors();

        for tv in test_vectors {
            //
            // Load the test vector components
            //

            // Recipient key material
            let ivk = PreparedIncomingViewingKey::new(
                &IncomingViewingKey::from_bytes(&tv.incoming_viewing_key).unwrap(),
            );
            let ovk = OutgoingViewingKey::from(tv.ovk);
            let d = Diversifier::from_bytes(tv.default_d);
            let pk_d = DiversifiedTransmissionKey::from_bytes(&tv.default_pk_d).unwrap();

            // Received Action
            let cv_net = ValueCommitment::from_bytes(&tv.cv_net).unwrap();
            let nf_old = Nullifier::from_bytes(&tv.nf_old).unwrap();
            let rho = Rho::from_nf_old(nf_old);
            let cmx = ExtractedNoteCommitment::from_bytes(&tv.cmx).unwrap();

            let esk = EphemeralSecretKey::from_bytes(&tv.esk).unwrap();
            let ephemeral_key = EphemeralKeyBytes(tv.ephemeral_key);

            // Details about the expected note
            let value = NoteValue::from_raw(tv.v);
            let rseed = RandomSeed::from_bytes(tv.rseed, &rho).unwrap();

            //
            // Test the individual components
            //

            let shared_secret = esk.agree(&pk_d);
            assert_eq!(shared_secret.to_bytes(), tv.shared_secret);

            let k_enc = shared_secret.kdf_orchard(&ephemeral_key);
            assert_eq!(k_enc.as_bytes(), tv.k_enc);

            let ock = prf_ock_orchard(&ovk, &cv_net, &cmx.to_bytes(), &ephemeral_key);
            assert_eq!(ock.as_ref(), tv.ock);

            let recipient = Address::from_parts(d, pk_d);
            let note_version = NoteVersion::V2;
            let note = Note::from_parts(recipient, value, rho, rseed, note_version).unwrap();
            assert_eq!(ExtractedNoteCommitment::from(note.commitment()), cmx);

            let action = Action::from_parts(
                // nf_old is the nullifier revealed by the receiving Action.
                nf_old,
                // We don't need a real rk for this test.
                redpallas::VerificationKey::dummy(),
                cmx,
                TransmittedNoteCiphertext {
                    epk_bytes: ephemeral_key.0,
                    enc_ciphertext: tv.c_enc,
                    out_ciphertext: tv.c_out,
                },
                cv_net.clone(),
                (),
            )
            .expect("a key returned by VerificationKey::dummy() is vanishingly unlikely to be the identity");

            //
            // Test decryption
            // (Tested first because it only requires immutable references.)
            //

            let domain = OrchardDomain::from_rho(rho);

            match try_note_decryption(&domain, &ivk, &action) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Note decryption failed"),
            }

            match try_compact_note_decryption(&domain, &ivk, &CompactAction::from(&action)) {
                Some((decrypted_note, decrypted_to)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                }
                None => panic!("Compact note decryption failed"),
            }

            match try_output_recovery_with_ovk(&domain, &ovk, &action, &cv_net, &tv.c_out) {
                Some((decrypted_note, decrypted_to, decrypted_memo)) => {
                    assert_eq!(decrypted_note, note);
                    assert_eq!(decrypted_to, recipient);
                    assert_eq!(&decrypted_memo[..], &tv.memo[..]);
                }
                None => panic!("Output recovery failed"),
            }

            //
            // Test encryption
            //

            let ne = OrchardNoteEncryption::new_with_esk(esk, Some(ovk), note, tv.memo);

            assert_eq!(ne.encrypt_note_plaintext().as_ref(), &tv.c_enc[..]);
            assert_eq!(
                &ne.encrypt_outgoing_plaintext(&cv_net, &cmx, &mut OsRng)[..],
                &tv.c_out[..]
            );
        }
    }

    #[test]
    fn domains_accept_only_their_note_plaintext_versions() {
        let mut rng = OsRng;
        let sk = crate::keys::SpendingKey::random(&mut rng);
        let fvk = crate::keys::FullViewingKey::from(&sk);
        let recipient = fvk.address_at(0u32, crate::keys::Scope::External);
        let rho = Rho::from_nf_old(Nullifier::dummy(&mut rng));
        let memo = [0u8; 512];

        let note_v2 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V2,
            &mut rng,
        );
        let note_v3 = Note::new(
            recipient,
            NoteValue::from_raw(5),
            rho,
            NoteVersion::V3,
            &mut rng,
        );
        let orchard_domain = OrchardDomain::from_rho(rho);
        let ironwood_domain = IronwoodDomain::from_rho(rho);

        let np_v2 = OrchardDomain::note_plaintext_bytes(&note_v2, &memo);
        let np_v3 = IronwoodDomain::note_plaintext_bytes(&note_v3, &memo);
        let pk_d = recipient.pk_d();

        assert_eq!(
            orchard_domain
                .parse_note_plaintext_without_memo_ovk(pk_d, &np_v2)
                .map(|(note, _)| note),
            Some(note_v2)
        );
        assert_eq!(
            ironwood_domain
                .parse_note_plaintext_without_memo_ovk(pk_d, &np_v3)
                .map(|(note, _)| note),
            Some(note_v3)
        );
        assert!(orchard_domain
            .parse_note_plaintext_without_memo_ovk(pk_d, &np_v3)
            .is_none());
        assert!(ironwood_domain
            .parse_note_plaintext_without_memo_ovk(pk_d, &np_v2)
            .is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_encrypted_outputs() {
        let (action, ivk, note, recipient, memo) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);

        assert_eq!(
            try_note_decryption(&domain, &ivk, &action),
            Some((note, recipient, memo))
        );
    }

    #[cfg(feature = "unsafe-zns")]
    #[test]
    fn zns_ironwood_domain_releases_a_note_only_after_caller_validation() {
        let (action, ivk, note, recipient, memo) = v3_nonstandard_commitment_action();

        // The standard rule derives the commitment from rseed and therefore
        // correctly rejects this nonstandard commitment.
        assert!(
            try_note_decryption(&IronwoodDomain::for_action(&action), &ivk, &action).is_none()
        );

        let domain = ZnsIronwoodDomain::for_action(&action);
        assert_eq!(
            domain.try_decrypt(&action, &ivk, |decrypted, decrypted_memo, cmx| {
                // ZcashName commitment derivation is intentionally caller-owned.
                if decrypted == &note && decrypted_memo == &memo && cmx == action.cmx() {
                    subtle::Choice::from(1)
                } else {
                    subtle::Choice::from(0)
                }
            }),
            Some((note, recipient, memo)),
        );

        let domain = ZnsIronwoodDomain::for_action(&action);
        assert!(domain
            .try_decrypt(&action, &ivk, |_, _, _| subtle::Choice::from(0))
            .is_none());
    }

    #[test]
    fn orchard_domain_rejects_v3_encrypted_outputs() {
        let (action, ivk, _, _, _) = v3_encrypted_action();
        let domain = OrchardDomain::for_action(&action);

        assert!(try_note_decryption(&domain, &ivk, &action).is_none());
    }

    #[test]
    fn ironwood_domain_decrypts_v3_compact_outputs() {
        let (action, ivk, note, recipient, _) = v3_encrypted_action();
        let domain = IronwoodDomain::for_action(&action);
        let compact = CompactAction::from(&action);

        assert_eq!(
            try_compact_note_decryption(&domain, &ivk, &compact),
            Some((note, recipient))
        );
    }
}
