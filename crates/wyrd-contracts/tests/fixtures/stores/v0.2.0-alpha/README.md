# v0.2.0-alpha fixture

Release baseline for the upgrade contracts, produced by
`regenerate_release_fixture` (ignored, run explicitly) through the public
delivery path: genesis and admission transitions plus an epoch-1..2
capability for the deterministic `device(0x20)` recipient, store
passphrase `contracts`. Frozen store bytes: `upgrade_previous_release_store_replays`
replays exactly these files, so regenerating them by hand breaks
the pin — re-run the generator instead.
