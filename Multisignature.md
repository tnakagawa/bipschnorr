# Multisignature

This sentence is a procedure for n-of-n Multisignatures to the following URL.

The symbols and functions used are defined in the following URL.

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki


## Introduction

- The number of users u.
- The public key P = P<sub>1</sub> + ... + P<sub>u</sub> : a point
- The message m: an array of 32 bytes

The n , G and functions are cited from the original text.

## Signing

### Step 1

Every user(i = 1...u) prepare secret key , random point and hash value.

- The secret key d<sub>i</sub>: an integer in the range 1..n-1.
- Let k<sub>i</sub> = int(hash(bytes(d<sub>i</sub>) || m)) mod n.
- Let R<sub>i</sub> = k<sub>i</sub>G.
- Let h<sub>i</sub> = hash(bytes(R<sub>i</sub>)).

### Step 2

Every user(i = 1...u) sends hash value (h<sub>i</sub>) to other users(j = 1...u , i &ne; j).

### Step 3

If all hash values are received, users(i = 1...u) send random point(R<sub>i</sub>) to other users(j = 1...u , i &ne; j).

### Step 4

Every user(i = 1...u) checks :

- For j = 1...u , i &ne; j:
    - Let h = hash(bytes(R<sub>j</sub>)).
    - Fail if h<sub>j</sub> &ne; h.

Every user(i = 1...u) sign :

- Let k<sub>i</sub> = int(hash(bytes(d<sub>i</sub>) || m)) mod n.
- Let R = R<sub>1</sub> + ... + R<sub>u</sub>.
- If jacobi(y(R)) &ne; 1 , let k<sub>i</sub> = n - k<sub>i</sub>.
- Let e = int(hash(bytes(x(R)) || bytes(P) || m)) mod n.
- Let s<sub>i</sub> = bytes(k<sub>i</sub> + ed<sub>i</sub> mod n).

Every user(i = 1...u) sends their signature(s<sub>i</sub>) to other users(j = 1...u , i &ne; j).

### Step 5

Every user(i = 1...u) checks:

- Let R = R<sub>1</sub> + ... + R<sub>u</sub>.
- Let e = int(hash(bytes(x(R)) || bytes(P) || m)) mod n.
- For j = 1...u , i &ne; j:
    - Fail if s<sub>j</sub> &ge; n.
    - Let R = s<sub>j</sub>G - eP<sub>j</sub>
    - Fail if infinite(R') or x(R) &ne; x(R<sub>j</sub>).

### Step 6

Any user creates a signature :

- Let R = R<sub>1</sub> + ... + R<sub>u</sub>.
- Let s = s<sub>1</sub> + ... + s<sub>u</sub> mod n.
- The signature is bytes(x(R)) || bytes(s).

