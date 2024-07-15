# CCC Locks Overview
## Introduction
[CCC (Common Chains Connector)](https://github.com/ckb-ecofund/ccc) helps
developers interoperate wallets from different chain ecosystems with CKB, fully
enabling CKB's cryptographic freedom power. In this overview specification, we
describe some common designs, definitions, and conventions. The lock
specifications for dedicated chains can be found in other documents. The
definitions and conventions in this section apply to all CCC lock
specifications, including BTC, ETH, and more.


## `ckbhash`
CKB uses blake2b as the default hash algorithm. We use `ckbhash` to denote the
blake2b hash function with following configuration:

- output digest size: 32
- personalization: ckb-default-hash

The `blake160` function is defined to return the leading 20 bytes of the `ckbhash` result.


## sighash_all

A 32-byte `sighash_all` message can be calculated via `ckbhash` with following data:

* Transaction hash
* Witness length and content in same script group covered by inputs, excluding lock field
* Other witness length and content that not covered by inputs

A reference implementation in C can be found [here](https://github.com/nervosnetwork/ckb-system-scripts/blob/a7b7c75662ed950c9bd024e15f83ce702a54996e/c/secp256k1_blake160_sighash_all.c#L219).

## WitnessArgs
When unlocking a CCC lock script, the corresponding witness must be a proper
`WitnessArgs` data structure in molecule format. In the lock field of the
WitnessArgs, a signature must be present. Signatures can be different for
different chains.

## Hexadecimal String
Only lowercase letters can be used in hexadecimal strings. For example, "00" and
"ffee" are valid hexadecimal strings, while "FFEE" and "hello world" are not
valid. 

## Links
- [BTC](./btc.md)
- ETH
