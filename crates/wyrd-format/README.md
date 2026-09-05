# wyrd-format

Wyrd's core object model: two identity worlds, canonical encoding,
content-defined chunking, Merkle file trees, and the snapshot DAG.

## What belongs here

- The `Hash` type and both identities (Content ID, Storage ID) with their
  domain-separated BLAKE3 derivations
- FastCDC chunking and the chunk contract (16/64/256 KiB, frozen at v1)
- The canonical object envelope (`wyrd ‖ version ‖ kind ‖ payload`)
- File/tree entry model for the content drive (paths, kinds, exec bit,
  symlink targets) and the explicit unsupported-metadata list
- Snapshot DAG types: parents, heads, conflicts-as-forks
- `ObjectStore` and its filesystem implementation(s)

## What does not belong here

Anything with I/O beyond local object storage: no networking, no async, no
keys or encryption (the format layer is the plaintext world — sync owns
keys, ciphertext, and manifests), no FUSE.

## Rules

- Dependency-light by rule: blake3, hex, thiserror, serde when serialization
  lands. Anything heavier needs a very good reason.
- Objects are immutable. Identical content always yields the identical
  Content ID; putting it twice is a no-op.
- Content IDs never appear in vault-visible metadata — but enforcing that is
  the sync layer's job; this crate simply defines the two identities and
  keeps them from drifting together.

