use wyrd_format::Snapshot;

/// A snapshot that may cross the head boundary: verification already
/// happened upstream, and this trait is the only way to name it.
///
/// `VerifiedSnapshot` is an **unsafe capability**, not a general
/// conversion trait: it exists to install a cryptographically verified
/// snapshot as a FUSE view head — nothing else. The boundary is
/// safe-by-default, not compile-enforced: crossing it requires an
/// explicit `unsafe impl`. The orphan rule prevents implementing the
/// capability directly for a foreign `Snapshot`; the unsafe contract
/// makes wrapper-based bypasses an explicit, auditable trust assertion.
/// The seal is `unsafe`-audited at two points by design, and both are
/// greppable: minting the proof token is sync's one audited crossing
/// (`wyrd_sync::durable::AuthorizeSnapshot::authorize`, pinned by
/// contract 34's crossing-count check), while installing a head is
/// this trait's audited `unsafe impl`. Every `unsafe impl` is a
/// visible claim that the implementing type's construction is owned
/// by the verification authority. In-tree the production impl is
/// exactly one: `wyrd_namespace::view::Head`, whose inner
/// `AuthorizedSnapshot` sync's BIP-340 verification alone may mint;
/// every other in-tree impl is a deliberately forged test fixture
/// documented as asserting nothing real. The token proves a
/// drive-bound signature only — head eligibility is decided at
/// composition (`WyrdNode::refresh_live_heads`), so a view built
/// from otherwise-obtained tokens can project retained history.
///
/// A downstream wrapper around a raw snapshot cannot implement the
/// capability in safe code — the audit marker is the only way across:
///
/// # Safety
///
/// Implementors assert that the wrapped snapshot's signature has been
/// verified by the trust authority (in-tree: `wyrd-sync`'s
/// `AuthorizedSnapshot` construction), so a false `unsafe impl` puts an
/// unverified body in the live view. Keep implementations few, local to
/// the composing crate, and review each like an `unsafe` block.
///
/// ```compile_fail
/// use wyrd_fuse::VerifiedSnapshot;
/// use wyrd_format::Snapshot;
///
/// struct Unchecked(Snapshot);
///
/// // A local wrapper type around a foreign `Snapshot`: the orphan
/// // rule allows this impl shape, but the capability is unsafe, so
/// // implementing it in safe code does not compile — an unverified
/// // snapshot has no quiet path to a view head.
/// impl VerifiedSnapshot for Unchecked {
///     fn into_snapshot(self) -> Snapshot {
///         self.0
///     }
/// }
/// ```
// The one intentional unsafe surface in this crate: the capability
// declaration itself. Everything else holds the workspace-wide
// `unsafe_code` deny.
#[allow(unsafe_code)]
pub unsafe trait VerifiedSnapshot {
    /// The verified snapshot body. Consuming preserves the one-way
    /// flow: a head is built from verified material and never exposed
    /// as bare, re-wrappable state.
    fn into_snapshot(self) -> Snapshot;
}

/// One installed head: a snapshot that entered the view only through
/// the verification capability. The body is unreachable except as the
/// view's own head state.
pub struct ViewHead {
    pub(crate) snapshot: Snapshot,
}

impl ViewHead {
    /// Install a verified snapshot as a head.
    pub fn new(verified: impl VerifiedSnapshot) -> Self {
        ViewHead {
            snapshot: verified.into_snapshot(),
        }
    }
}

// SAFETY: `wyrd_namespace::view::Head` wraps the proof token sync's
// BIP-340 verification alone may mint (single audited crossing, see
// the trait docs) — the same trust claim as the daemon's former
// `LiveHead`, carried by the type instead of a second wrapper. This
// is the one production crossing from verified sync state into view
// heads.
#[allow(unsafe_code)]
unsafe impl VerifiedSnapshot for wyrd_namespace::view::Head {
    fn into_snapshot(self) -> Snapshot {
        wyrd_namespace::view::Head::into_snapshot(self)
    }
}
