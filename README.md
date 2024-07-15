# CCC Locks

[CCC (Common Chains Connector)](https://github.com/ckb-ecofund/ccc) helps
developers interoperate wallets from different chain ecosystems with CKB, fully
enabling CKB's cryptographic freedom power. The lock specifications for
dedicated chains can be found in [docs](./docs/).


## Build

Build on native machine:
```
make build
```
See [ckb-script-templates](https://github.com/cryptape/ckb-script-templates) for required setup.


Make a reproducible build:
```
bash scripts/reproducible_build_docker
```
The docker is required.


## Test

```
cd tests && cargo test
```

