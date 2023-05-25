# Share Generator

A cli tool for generating & deriving key share for local fairyring testnet

## Build

```bash
go install
go build
```

## Usage

### Generate Shares

```bash
./ShareGenerator generate [number of validator] [threshold]
```

#### Example

Generate shares with total 1 validator & threshold as 1

```
> ./ShareGenerator generate 1 1 | jq '.'

{
  "Shares": [
    {
      "Value": "4e4de78f3823e222c63de342c5aa995b25f794f2b118b9b52c82565792ea14f5",
      "Index": 0
    }
  ],
  "MasterPublicKey": "b584990d7022c6989633b0d443ffc5fc1128b4107cac25904d526d12536153c34349e5f3657870a498ccf6f78a858085",
  "Commitments": [
    "b584990d7022c6989633b0d443ffc5fc1128b4107cac25904d526d12536153c34349e5f3657870a498ccf6f78a858085"
  ]
}
```

---

### Derive Share for specific height

```bash
./ShareGenerator derive [share-in-hex] [share-index] [height]
```

#### Example

Derive the given key share for block height 100

```
> ./ShareGenerator derive 4e4de78f3823e222c63de342c5aa995b25f794f2b118b9b52c82565792ea14f5 0 100 | jq '.'

{
  "KeyShare": "87898dd7ee0cafc32f9ef45893df6be5fba5c82ae633323d6a7c574e47476898bca35ce4d553b6b6b31bf8e8f328f9470fce88c232ffe51bce3f90b827d50abbfcb1dc2eff5e3ae9ee7789edfe84593ff56e24ab1eaa5861eec519f5eb4a4a8a",
  "Commitment": "b584990d7022c6989633b0d443ffc5fc1128b4107cac25904d526d12536153c34349e5f3657870a498ccf6f78a858085"
}
```