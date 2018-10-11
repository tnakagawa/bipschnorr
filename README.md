# bipschnorr

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

## Test

```bash
$ go get github.com/btcsuite/btcd/btcec
$ go get -u github.com/tnakagawa/bipschnorr
$ go test -count 1 -v github.com/tnakagawa/bipschnorr
```

## Draft

```bash
$ go get github.com/btcsuite/btcd/btcec
$ go get -u github.com/tnakagawa/bipschnorr
```

- [Multisignature](https://gist.github.com/tnakagawa/0c3bc74a9a44bd26af9b9248dfbe598b)

```bash
$ go test -count 1 -v github.com/tnakagawa/bipschnorr -run ^TestMultisignature$
```

- [Threshold Signatures](https://gist.github.com/tnakagawa/e6cec9a89f698997dc58a09db541e1eb)

```bash
$ go test -count 1 -v github.com/tnakagawa/bipschnorr -run ^TestThreshold$
```
