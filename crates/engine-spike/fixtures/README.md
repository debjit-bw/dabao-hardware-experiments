# Fixtures

- `guest-smoke.in.ssz` / `guest-smoke.out.ssz`: SSZ input and expected output of the
  stateless guest, decoded from `testing/stateless-validator/fixtures/guest-smoke.json`
  in paradigmxyz/stateless @ `reth-guest-v0.1.0-rc.9`. Test case:
  `tests/amsterdam/eip7928_block_level_access_lists/test_block_access_lists_eip4788.py::test_bal_4788_absent_contract[fork_Amsterdam-blockchain_test]#block0`
  (an Amsterdam block from execution-specs `tests-zkevm`).
