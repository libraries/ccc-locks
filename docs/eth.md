# CCC Ethereum Lock Specification
This specification describes a CCC lock script that can interoperate with the
Ethereum blockchain. Some common designs, definitions, and conventions can be found
in the [overview](./overview.md).

## Lock Script
A CCC Ethereum lock script has following structure:
```
Code hash: CCC Ethereum lock script code hash
Hash type: CCC Ethereum lock script hash type
Args:  <secp256k1 pubkey hash, 20 bytes>
```

The secp256k1 pubkey hash is calculated via the following procedure(referred as keccak160):

1. Perform a [Keccak](https://github.com/ethereum/eth-hash) hash over the uncompressed secp256k1 pubkey (64 bytes).
2. Take the trailing 20 bytes of the hash result.

The secp256k1 pubkey hash can be also decoded from an Ethereum address in
hexadecimal format. 


## Witness
The corresponding witness must be a proper `WitnessArgs` data structure in
molecule format. In the lock field of the WitnessArgs, a 65 bytes secp256k1
signature must be present.

The last byte of the signature is the `v` value described in Ethereum yellow paper
(324). This `v` can only be 27 or 28 and other values are rejected. The `r` and
`s` values precede it. The `recId` is derived from `v` using the formula `v -
27`.

## Unlocking Process
The following bytes are hashed via Keccak hashing:

1. A byte representing the length of the following string (25).
2. A string with 25 bytes: "Ethereum Signed Message:\n".
3. Three bytes representing the length of the following string. It is in decimal
   string format(e.g. "155", "166"). Note that this format is different from the
   length used in step 1.
4. A string with bytes:

"Signing a CKB transaction: 0x{sigh_hash}\n\nIMPORTANT: Please verify the integrity and authenticity of connected Ethereum wallet before signing this message\n"

The `{sighasl_all}` is replaced by `sighash_all` in hexadecimal string, with length 64. The
string in the last part can be displayed in wallet UIs.

After hashing, this hash value is the message used in secp256k1 verification.
The signature with `recId` is used to recover uncompressed pubkey, according to
the message above. If the keccak160 on uncompressed pubkey is identical to
script args, then the script is validated successfully.

## Examples

```yaml
CellDeps:
    <vec> CCC Ethereum lock script cell
Inputs:
    <vec> Cell
        Data: <...>
        Type: <...>
        Lock:
            code_hash: <CCC Ethereum lock script code hash>
            args: <secp256k1 pubkey hash, 20 bytes>
Outputs:
    <vec> Any cell
Witnesses:
    <vec> WitnessArgs
      Lock: <r, 32 bytes> <s, 32 bytes> <v, 1 byte> 
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
| `code_hash` | 0x5b1983cf4242009f72e82b37fb6b36790e6d4858474046fc3c798e5142cf8835   |
| `hash_type` | `type`                                                               |
| `tx_hash`   | 0x2e6a50a9ce96c7b9697ed0fd21bd0a736d3df5e62d25137f728d8354a36cb369   |
| `index`     | `0x0`                                                                |
| `dep_type`  | `code`                                                               |

Reproducible build is supported to verify the deployed script. To build the
deployed script above, one can use the following steps:

```bash
git clone https://github.com/ckb-ecofund/ccc-locks.git
cd ccc-locks
git checkout 87ac79
bash scripts/reproducible_build_docker
```

