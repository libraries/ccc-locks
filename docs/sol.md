# CCC Solana Lock Specification

This specification describes a CCC lock script that can interoperate with the Solana blockchain. Some common designs, definitions, and conventions can be found in the [overview](./overview.md).

## Lock Script

A CCC Solana lock script has following structure:

```
Code hash: CCC Solana lock script code hash
Hash type: CCC Solana lock script hash type
Args:  <ed25519 pubkey, 32 bytes>
```

The ed25519 pubkey can be also decoded from an Solana address by base58 decoding.

## Witness

The corresponding witness must be a proper `WitnessArgs` data structure in molecule format. In the lock field of the WitnessArgs, a 64 bytes ed25519 signature must be present.

## Unlocking Process

Ed25519 messages can be of any length and does not require hashing. Specifically, for the CCC Solana lock, the message is:

"Signing a CKB transaction: 0x{sigh_hash}\n\nIMPORTANT: Please verify the integrity and authenticity of connected Solana wallet before signing this message\n"

The `{sighasl_all}` is replaced by `sighash_all` in hexadecimal string, with length 64. The string in the last part can be displayed in wallet UIs.

For the ed25519 message, signature, and pubkey, the ed25519 verify function is used. If the verification passes, the signature is successfully verified.

## Examples

```yaml
CellDeps:
    <vec> CCC Solana lock script cell
Inputs:
    <vec> Cell
        Data: <...>
        Type: <...>
        Lock:
            code_hash: <CCC Solana lock script code hash>
            args: <ed25519 pubkey, 32 bytes>
Outputs:
    <vec> Any cell
Witnesses:
    <vec> WitnessArgs
      Lock: <signature, 64 bytes>
```



## Notes

An implementation of the lock script spec above has been deployed to CKB mainnet and testnet:

- mainnet

| parameter   | value                                                                |
| ----------- | -------------------------------------------------------------------- |
| `code_hash` | TODO   |
| `hash_type` | `type`                                                               |
| `tx_hash`   | TODO   |
| `index`     | `0x0`                                                                |
| `dep_type`  | `code`                                                               |

- testnet

| parameter   | value                                                                |
| ----------- | -------------------------------------------------------------------- |
| `code_hash` | TODO   |
| `hash_type` | `type`                                                               |
| `tx_hash`   | TODO   |
| `index`     | `0x0`                                                                |
| `dep_type`  | `code`                                                               |

Reproducible build is supported to verify the deployed script. To build the deployed script above, one can use the following steps:

```bash
TODO
```
