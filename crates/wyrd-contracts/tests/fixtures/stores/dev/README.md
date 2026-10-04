# dev fixture

Harness smoke fixture for the upgrade contracts, produced by
`regenerate_dev_fixture` (ignored, run explicitly) through the public
delivery path: genesis and admission transitions plus an epoch-1..2
capability for the deterministic `device(0x20)` recipient, store
passphrase `contracts`. Never cross-version evidence: per-release
fixtures land under their tag; the `v0.2.0-alpha` release cut the
first one alongside this `dev` smoke fixture.
