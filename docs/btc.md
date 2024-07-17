# CCC BTC Lock Specification
This specification describes a CCC lock script that can interoperate with the
BTC blockchain. Some common designs, definitions, and conventions can be found
in the [overview](./overview.md).

## Lock Script
A CCC BTC lock script has following structure:
```
Code hash: CCC BTC lock script code hash
Hash type: CCC BTC lock script hash type
Args:  <secp256k1 pubkey hash, 20 bytes>
```
This secp256k1 pubkey hash is calculate via SHA-256 and RIPEMD-160 over
compressed secp256k1 pubkey(33 bytes).

## Supported BTC Addresses
The following address types are supported:
- P2PKH
- P2WPKH

The secp256k1 pubkey hash can be decoded from address via base58 or bech32m(bech32).


## Witness
The corresponding witness must be a proper `WitnessArgs` data structure in
molecule format. In the lock field of the WitnessArgs, a 65 bytes secp256k1
signature must be present.

The first byte of the signature is the `header` described in [BIP
0137](https://github.com/bitcoin/bips/blob/master/bip-0137.mediawiki#procedure-for-signingverifying-a-signature).
The `r` and `s` values follow it. The `header` can accept following value ranges:
- 0~3
- 27~30 (P2PKH)
- 39-42 (P2WPKH)

They will be converted into 0~3 as `recId`.


## Unlocking Process
The following bytes are hashed via SHA-256 over SHA-256 (double SHA-256):

1. A byte representing the length of the following string (24).
2. A string with 24 bytes: "Bitcoin Signed Message:\n".
3. A byte representing the length of the following string.
4. A string with bytes:

"Signing a CKB transaction: 0x{sigh_hash}\n\nIMPORTANT: Please verify the integrity and authenticity of connected BTC wallet before signing this message\n"

The `{sighasl_all}` is replaced by `sighash_all` in hexadecimal string, with length 64. The
string in the last part can be displayed in wallet UIs.

After hashing, this hash value is the message used in secp256k1 verification.
The signature with `recId` is used to recover pubkey(compressed), according to
the message above. If the SHA-256 and RIPEMD-160 over recovered compressed
pubkey is identical to script args, then the script is validated successfully.

## Examples

```yaml
CellDeps:
    <vec> CCC BTC lock script cell
Inputs:
    <vec> Cell
        Data: <...>
        Type: <...>
        Lock:
            code_hash: <CCC BTC lock script code hash>
            args: <secp256k1 pubkey hash, 20 bytes>
Outputs:
    <vec> Any cell
Witnesses:
    <vec> WitnessArgs
      Lock: <recId, 1 byte> <r, 32 bytes> <s, 32 bytes>
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

Reproducible build is supported to verify the deployed script. To build the
deployed script above, one can use the following steps:

```bash
TODO
```

