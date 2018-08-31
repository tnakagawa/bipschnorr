# bipschnorr

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

## Test

```bash
$ go get -u github.com/tnakagawa/bipschnorr
$ go test -count 1 -v github.com/tnakagawa/bipschnorr
```

## Draft

```bash
$ go get -u github.com/tnakagawa/bipschnorr
```

- [Multisignature](./Multisignature.md)

```bash
$ go test -count 1 -v github.com/tnakagawa/bipschnorr -run ^TestMultisignature$
```

- [Threshold](./Threshold.md)

```bash
$ go test -count 1 -v github.com/tnakagawa/bipschnorr -run ^TestThreshold$
```
