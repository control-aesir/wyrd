# Release & distribution strategy for wyrd

Quick read before the details: none of this needs new trust infrastructure. Wyrd already has Nostr identity, BIP-340 signing, and a content-addressing model baked into the storage layer — the recommendations below mostly reuse what's already in `wyrd-sync/src/keys/` rather than bolting anything foreign on.

One clarifying point first: **grasp.t5.st and gitworkshop.dev are GRASP servers** — Git hosting plus a Nostr relay for repository state, issues, and PRs. That's a different protocol from Blossom (blob storage). Having GRASP infrastructure today doesn't give you Blossom hosting for free; that's a separate decision (Q1).

| # | Question | Pre-alpha recommendation | Revisit when |
|---|---|---|---|
| 1 | Artifact hosting | Dual-publish to 3–5 public Blossom servers via BUD-04 mirroring; no self-hosted server yet | A free server rate-limits you, or you want retention independent of any one host's goodwill |
| 2 | Release publishing | `ngit release publish` only (NIP-82 + Blossom); skip a GitHub mirror | You need a non-nostr on-ramp for growth |
| 3 | Update notifications | Same relay subscription the daemon already holds open; no separate check server | Never — this scales fine |
| 4 | Update mechanics | Notify-and-manual, sequenced unmount → replace → remount | You operate a fleet of headless vault/server nodes |
| 5 | Signing & verification | Pin the maintainer npub now; move signing to a Frostr threshold key before it's load-bearing | You have >1 maintainer, or before mainnet-grade trust matters |
| 6 | Web presence | nsite via `ngit nsite publish`, public gateways for redundancy, a free static redirect for the memorable URL | Never need your own gateway |
| 7 | Mobile stores | Plan Android and iOS as separate pipelines from day one in docs/mobile.md | N/A — this is architectural, decide now |

---

### 1. Artifact hosting

Blossom's whole design point is that content addressing (SHA-256 of the blob) *is* the verification, so any of several mirrors can serve the same bytes and a client checks the hash locally rather than trusting the transport— files are identified by the SHA-256 hash of their bytes, so a client can hand the same hash to several Blossom servers and any of them can serve the file back, with no central registry to maintain. That maps directly onto wyrd's own `StorageId` concept, so adopting it costs nothing conceptually.

Don't self-host yet. Publish binaries to a handful of established public servers, publish your own BUD-03 server list (kind:10063) advertising themas a tagged list of server URLs the client can fetch from, and use BUD-04's mirror endpoint so you upload once and ask other servers to pull from that first upload rather than re-uploading from your own bandwidth N times. Some public servers are free with size/retention limits, others require BUD-07 payment for guaranteed retention — check the specific servers you pick rather than assuming either model. Bandwidth cost, in this setup, sits with whichever public operator you chose; that's exactly the "someone else feeds this pet" outcome your philosophy wants at this stage.

Self-hosting becomes worth it only as a *fourth or fifth mirror*, never as the sole source — the moment it's your only Blossom server you've recreated the single point of failure the protocol exists to avoid.

### 2. Release publishing

Use `ngit release publish` and nothing else. ngit v3 shipped this specifically: signed NIP-82 release and application events, Blossom-replicated assets, Zapstore-compatible metadata, and the ngit project updates *itself* through this exact pipeline— publishing signed NIP-82 applications, releases, and assets with Zapstore-compatible metadata, then updating ngit itself from its verified releases. Since wyrd already lives exclusively on nostr git, this is zero new infrastructure: no GitHub account, no second signing key, no second build target to keep in sync.

Skip a GitHub mirror. Your stated distribution today is "nothing," and your audience right now is people already comfortable with `nostr://` clone URLs — a GitHub mirror mainly helps people who aren't nostr-native yet, which is a Q6 (web presence) concern, not a release-publishing one. A second platform is also a second thing that can drift out of sync with the signed canonical release, which is the opposite of what you want pre-alpha.

Discovery today is genuinely thin outside the ngit/Zapstore ecosystem — that's an honest limitation, not something to route around with a GitHub mirror. Publishing NIP-82-compliant metadata from day one at least means wyrd is automatically eligible for Zapstore's catalog later without extra work, since Zapstore already supports the same publishing flow for desktop binaries and CLI tools as it does for Android apps.

### 3. Update notifications

Don't build a separate check mechanism — subscribe to your own release events on relays you're already connected to. ngit itself does exactly this, warning when a newer version is available and offering both an interactive and scriptable checkvia `ngit update` and `ngit update --check`, backed by ngit's signed repository state and trusted NIP-82 release assets, building on an earlier release's plain version-check warningthat warns when a newer ngit version is available.

For headless nodes this answers itself: a release announcement is just a Nostr event, and a subscribing client is no different running unattended than running interactively. wyrd-daemon already needs persistent relay connections for its normal sync duties — reuse that connection for one more filter rather than standing up anything new. Note that "relay announcement" and "check against Blossom" in your question aren't actually alternatives: the relay event is the *discovery* layer, Blossom is the *delivery* layer for the bytes it points to. You need both, together, not one instead of the other.

### 4. Update mechanics

Go notify-and-manual, not auto-update — and this is a place where wyrd's situation is genuinely different from ngit's own. ngit invokes fresh on every command with no persistent state to protect, so its policy of auto-replacing only receipted standalone installs, and giving Nix/Cargo installs non-mutating guidance insteadso that only receipted standalone Unix installations are replaced automatically, while Nix, Cargo, and unreceipted installations receive non-mutating guidance, is safe for it. wyrd-daemon is a long-lived process potentially holding a live FUSE mount with unflushed encrypted writes and open sync state — silently swapping the binary underneath that risks a mid-mutation cross-version read or a stuck mount.

Concretely: `wyrd update` should signal the daemon to quiesce, flush, cleanly unmount, verify the unmount succeeded, replace the binary atomically (download to a temp path, verify its hash against the signed release manifest, rename over), restart, remount. That's the same sequence a manual upgrade runbook needs anyway — packaging it as one command is mostly operational, not new engineering. Auto-update is worth revisiting only for headless vault/server roles with no mount to protect, and only once you have actual fleets, not speculatively.

### 5. Signing & verification

Pin the maintainer npub in the client now — that's free, since BIP-340 verification is already in the codebase. The harder question is rotation, because a pinned key embedded in already-distributed clients has the same bootstrapping problem every update system eventually hits (TUF, apt's keyring, Sigstore all wrestle with it): how do existing installs learn about a new key without trusting the compromise you're rotating away from.

Frostr is the nostr-native answer, and it's mature enough to adopt now rather than bolt on later. It splits a key into k-of-n shares using FROST threshold signatures, and critically, a t-of-n quorum of shares can sign together while a single compromised share doesn't leak the key, and shares can be rotated and replaced without rotating the underlying identity. The npub — your pinned trust anchor — never has to change for routine rotations (a laptop reformatted, a maintainer added). The project has shipped past prototype: a v1 suite is now live across desktop, browser, server, CLI, web, and mobile. Since you're pre-alpha, starting the release-signing key as a Frostr threshold key from day one avoids ever having to solve "how do all existing installs learn about the new key" as a live-fire problem — that alone is worth the small setup cost now.

If you want to defer the Frostr dependency, a fallback is a self-describing rotation event signed by the *old* key attesting to the new one — conceptually identical to the epoch/membership transitions wyrd already models in `docs/epochs.md`. But that only works if the old key isn't already compromised, which is precisely the scenario rotation exists for — it's a weaker answer than threshold signing, not an equivalent one.

### 6. Web presence

This is the sharpest of the seven because it looks like a chicken-and-egg problem and mostly isn't. nsite publishes a site manifest as a Nostr event mapping paths to Blossom-hosted files, and because the manifest lives on Nostr and the files can be mirrored across Blossom servers, the site stays reachable through multiple gateways instead of depending on one web host. The gateway — not the visitor's browser — does the Nostr-aware work, resolving a URL like `<npub>.nsite-host.com` on the visitor's behalf. So a plain browser with zero Nostr software can already view it; what you actually need is *a* gateway to exist, and multiple public ones already do (nsite.lol, nwb.tf, nsite.run, among others).

Given you already have `docs/` as markdown and `ngit nsite publish` is a first-class command that snapshots and publishes a directoryas a root or named site, confirming every blob on every selected Blossom server before signing and publishing the manifest — this is minutes of tooling you already have, not new work. Rely on the existing public gateways for redundancy rather than running your own; running your own gateway as the *only* path in would recreate the single point of failure nsite exists to avoid.

For the "first landing before any Nostr-aware software" problem specifically: a memorable custom domain doesn't require conventional hosting, just a redirect — a static CNAME or a one-file redirect page on any free static host, pointing at one of the public gateways. That's not a pet (no update mechanism, no server logic), and it solves exactly this one problem without recreating a hosting stack.

### 7. Mobile stores

Plan this as two pipelines sharing only the build, not the trust model — decide the split now since it shapes `docs/mobile.md`'s architecture even before you write the adapters.

**Android** survives the transplant almost intact. Sideloading has always been an OS-level option, and Zapstore's Android client already exists specifically to let Nostr-signed, Blossom-hosted APKs be discovered and installed this way, verifying binaries before installation and letting users install software outside the control of a single platform owner, with the Android client the most mature part of the project today. Your NIP-82/Blossom scheme is directly reusable here; a Play Store listing stays optional, parallel infrastructure rather than a requirement.

**iOS** does not survive intact outside the EU. Apple's App Store review and code signing are mandatory for the large majority of users, and your Nostr signature becomes, at best, informational metadata inside an Apple-signed binary — the OS itself doesn't check it. Inside the EU, the DMA's sideloading obligation requires Apple to allow alternative marketplaces and direct installs, though gatekeepers may still apply proportionate security measures such as malware scanning, and Apple's own compliance layers a baseline "Notarization" review in front of everything regardless of source, so even there your signature is additive to an Apple gate, not a replacement for it. Consistent with that, comparable projects in this ecosystem — Frostr's Igloo, which is live on the App Store — went the conventional route rather than trying to bypass it.

Net effect: budget Android as "your scheme, basically as-is" and iOS as "a normal Apple developer account and review process regardless of what desktop looks like." The actual paperwork is a when-you-build-the-adapter problem; the two-pipeline architecture is the part worth deciding now.
