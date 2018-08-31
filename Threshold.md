# Threshold Signatures

This text is a procedure for t-of-k threshold signatures.

The symbols and functions used are defined in the following URL.

https://github.com/sipa/bips/blob/bip-schnorr/bip-schnorr.mediawiki

## Introduction

- The number of users k.
- The number of required signers t. ( 0 < t &le; k )
- The constant H refers to the generator. ( G &ne; H )
    - Let H = xG , x mod n , x is random.
- The message m : an array of 32 bytes

The n , G and functions are cited from the original text.

Each user i(i = 1...k) is in an agreed ordered set so that user i is always the same for every user.

## Shared Secret

### Step 1

Each user i(i = 1...k) sends t commitments to a set of random numbers:

- Let there be random numbers a<sub>i0</sub>...a<sub>i(t-1)</sub> and a'<sub>i0</sub>...a'<sub>i(t-1)</sub> in the range 1...n-1 , 2t integers.
- Let the sharing polynomials be f<sub>i</sub>(x) and f'<sub>i</sub>(x)
    - f<sub>i</sub>(x) = a<sub>i0</sub> + a<sub>i1</sub>x<sup>1</sup> + ... + a<sub>i(t-1)</sub>x<sup>t-1</sup>
    - f'<sub>i</sub>(x) = a'<sub>i0</sub> + a'<sub>i1</sub>x<sup>1</sup> + ... + a'<sub>i(t-1)</sub>x<sup>t-1</sup>
- Let the commitments be C<sub>i0</sub>...C<sub>i(t-1)</sub> : C<sub>ih</sub> = a<sub>ih</sub>G + a'<sub>ih</sub>H (h = 0...t-1).
- The user(i) sends commitments(C<sub>i0</sub>...C<sub>i(t-1)</sub>) to the other users(j = 1...k , j &ne; i).

### Step 2

Each user(i = 1...k) sends shared secrets and the other users' commitments to each other user:

- For j = 1...k , j &ne; i :
    - Let s<sub>ij</sub> = f<sub>i</sub>(j) mod n , s'<sub>ij</sub> = f'<sub>i</sub>(j)  mod n
    - The user(i) sends (s<sub>ij</sub> , s'<sub>ij</sub>) to the user(j).
    - The user(i) sends other user's commitments(C<sub>h0</sub>...C<sub>h(t-1)</sub> , h = 1...k , h &ne; i , h &ne; j)  to the user(j).

Each user(i = 1...k) verifies secret and commitments received from user(j = 1...k , j &ne; i) :

- Fail if s<sub>ji</sub>G + s'<sub>ji</sub>H &ne; i<sup>0</sup>C<sub>j0</sub> + ... + i<sup>t-1</sup>C<sub>j(t-1)</sub>
- Fail if commitments(C<sub>h0</sub>...C<sub>h(t-1)</sub>, h = 1...k , h &ne; i , h &ne; j) does not match commitments received at **Step 1**.
- If fail , sends result to other user(h = 1...k , h &ne; i).

### Step 3

Each user(i = 1...k) sends shared points :

- Let the A<sub>i0</sub>...A<sub>i(t-1)</sub> : A<sub>ih</sub> = a<sub>ih</sub>G (h = 0...t-1).
- The user(i) sends A<sub>i0</sub>...A<sub>i(t-1)</sub> to other users(j = 1...k , j &ne; i).


Each user(i = 1...k) verifies shared points received from user(j = 1...k , j &ne; i) :

- Fail if s<sub>ji</sub>G  &ne; i<sup>0</sup>A<sub>j0</sub> + ... + i<sup>t-1</sup>A<sub>j(t-1)</sub>
- If fail , sends result to other user(h = 1...k , h &ne; i).

The **publickey** of shared secret is sum of each 0-th points. : P = A<sub>10</sub> + ... + A<sub>k0</sub>

## Signing

- The t users participating in the signing process(u<sub>i</sub> , i = 1...t) .
- 1 &le; u<sub>i</sub> &le; k , i = 1...t ; u<sub>i1</sub> &ne; u<sub>i2</sub> , i1 &ne; i2 , 1 &le; i1 &le; t , 1 &le; i2 &le; t .

### Step 1

Each user u<sub>i</sub>(u<sub>i</sub> , i = 1...t) sends t commitments to a set of random numbers :

- Let there be random numbers b<sub>u<sub>i</sub>0</sub>...b<sub>u<sub>i</sub>(t-1)</sub> and b'<sub>u<sub>i</sub>0</sub>...b'<sub>u<sub>i</sub>(t-1)</sub> in the range 1...n-1 , 2t integers.
- Let the sharing polynomials be g<sub>u<sub>i</sub></sub>(x) and g'<sub>u<sub>i</sub></sub>(x)
    - g<sub>u<sub>i</sub></sub>(x) = b<sub>u<sub>i</sub>0</sub> + b<sub>u<sub>i</sub>1</sub>x<sup>1</sup> + ... + b<sub>u<sub>i</sub>(t-1)</sub>x<sup>t-1</sup>
    - g'<sub>u<sub>i</sub></sub>(x) = b'<sub>u<sub>i</sub>0</sub> + b'<sub>u<sub>i</sub>1</sub>x<sup>1</sup> + ... + b'<sub>u<sub>i</sub>(t-1)</sub>x<sup>t-1</sup>
- Let the commitments be C'<sub>u<sub>i</sub>0</sub>...C'<sub>u<sub>i</sub>(t-1)</sub> : C'<sub>u<sub>i</sub>h</sub> = b<sub>u<sub>i</sub>h</sub>G + b'<sub>u<sub>i</sub>h</sub>H (h = 0...t-1).
- The user(u<sub>i</sub>) sends commitments(C'<sub>u<sub>i</sub>0</sub>...C'<sub>u<sub>i</sub>(t-1)</sub>) to the other users(u<sub>j</sub> , j = 1...t , j &ne; i).

### Step 2

Each user(u<sub>i</sub> , i = 1...t) sends random numbers and the other user's commitments to each other user :

- For j = 1...t , j &ne; i :
    - Let r<sub>u<sub>i</sub>u<sub>j</sub></sub> = g<sub>u<sub>i</sub></sub>(u<sub>j</sub>) mod n , r'<sub>u<sub>i</sub>u<sub>j</sub></sub> = g'<sub>u<sub>i</sub></sub>(u<sub>j</sub>)  mod n
    - The user(u<sub>i</sub>) sends (r<sub>u<sub>i</sub>u<sub>j</sub></sub> , r'<sub>u<sub>i</sub>u<sub>j</sub></sub>) to the user(u<sub>j</sub>).
    - The user(u<sub>i</sub>) sends commitments(C'<sub>u<sub>h</sub>0</sub>...C'<sub>u<sub>h</sub>(t-1)</sub> , h = 1...t , h &ne; i , h &ne; j) of other users to the user(u<sub>j</sub>).

Each user(u<sub>i</sub> , i = 1...t) verifies random number and commitments received from user(u<sub>j</sub> , j = 1...t , j &ne; i) :

- Fail if r<sub>u<sub>j</sub>u<sub>i</sub></sub>G + r'<sub>u<sub>j</sub>u<sub>i</sub></sub>H &ne; u<sub>i</sub><sup>0</sup>C<sub>u<sub>j</sub>0</sub> + ... + u<sub>i</sub><sup>t-1</sup>C<sub>u<sub>j</sub>(t-1)</sub>
- Fail if commitments(C'<sub>u<sub>h</sub>0</sub>...C'<sub>u<sub>h</sub>(t-1)</sub> , h = 1...t , h &ne; i , h &ne; j) sent from user(i<sub>j</sub>) does not match commitments received at **Step 1**.
- If fail , sends result to other user(u<sub>h</sub> , h = 1...t , h &ne; i).

### Step 3

Each user(u<sub>i</sub> , i = 1...t) sends random points :

- Let the B<sub>u<sub>i</sub>0</sub>...B<sub>u<sub>i</sub>(t-1)</sub> : B<sub>u<sub>i</sub>h</sub> = b<sub>u<sub>i</sub>h</sub>G (h = 0...t-1).
- The user(u<sub>i</sub>) sends B<sub>u<sub>i</sub>0</sub>...B<sub>u<sub>i</sub>(t-1)</sub> to other users(u<sub>j</sub> , j = 1...t , j &ne; i).


Each user(u<sub>i</sub> , i = 1...t) verifies random points received from user(u<sub>j</sub> , j = 1...t , j &ne; i) :

- Fail if r<sub>u<sub>j</sub>u<sub>i</sub></sub>G  &ne; u<sub>i</sub><sup>0</sup>B<sub>u<sub>j</sub>0</sub> + ... + u<sub>i</sub><sup>t-1</sup>B<sub>u<sub>j</sub>(t-1)</sub>
- If fail , sends result to other user(u<sub>h</sub> , h = 1...t , h &ne; i).

The **Point** of random number is sum of each 0-th points. : R = B<sub>u<sub>1</sub>0</sub> + ... + B<sub>u<sub>t</sub>0</sub>

### Step 4

Each user(u<sub>i</sub> , i = 1...t) sends signature :

- Let r = r<sub>u<sub>1</sub>u<sub>i</sub></sub> + ... + r<sub>u<sub>t</sub>u<sub>i</sub></sub>
- Let R = B<sub>u<sub>1</sub>0</sub> + ... + B<sub>u<sub>t</sub>0</sub>
- If jacobi(y(R)) &ne; 1 , let r = n - r
- Let P = A<sub>10</sub> + ... + A<sub>k0</sub>
- Let e = int(hash(bytes(x(R)) || bytes(P) || m)) mod n
- Let s = s<sub>u<sub>1</sub>u<sub>i</sub></sub> + ... + s<sub>u<sub>k</sub>u<sub>i</sub></sub>
- Let sig<sub>u<sub>i</sub></sub> = r + es mod n
- The user(u<sub>i</sub>) sends sig<sub>u<sub>i</sub></sub> to other users(u<sub>j</sub> , j = 1...t , j &ne; i).

Each user(u<sub>i</sub> , i = 1...t) verifies signature received from user(u<sub>j</sub> , j = 1...t , j &ne; i) :

- Let B be the point at infinity
- For h = 1...t :
    - B = B + B<sub>u<sub>h</sub>0</sub>j<sup>0</sup> + ... + B<sub>u<sub>h</sub>(t-1)</sub>j<sup>t-1</sup>
- Let R = B<sub>u<sub>1</sub>0</sub> + ... + B<sub>u<sub>t</sub>0</sub>
- If jacobi(y(R)) &ne; 1 , let B = -B
- Let P = A<sub>10</sub> + ... + A<sub>k0</sub>
- Let e = int(hash(bytes(x(R)) || bytes(P) || m)) mod n
- Let A be the point at infinity
- For h = 1...k :
    - A = A + A<sub>u<sub>h</sub>0</sub>j<sup>0</sup> + ... + A<sub>u<sub>h</sub>(t-1)</sub>j<sup>t-1</sup>
- Fail if sig<sub>u<sub>j</sub></sub>G &ne; B + eA
- If fail , sends result to other user(u<sub>h</sub> , h = 1...t , h &ne; i).

### Step 5

Anyone holding sig and who knows the predefined user order can produce a valid signature:

- Let s = 0
    - For j = 1...t :
        - Let o = 1
        - For h = 1...t , u<sub>h</sub> &ne; u<sub>j</sub> :
            - o = o &times; u<sub>h</sub> &div; (u<sub>h</sub> - u<sub>j</sub>) mod n
        - s = s + o &times; sig<sub>u<sub>j</sub></sub> mod n
- Let R = B<sub>u<sub>1</sub>0</sub> + ... + B<sub>u<sub>t</sub>0</sub>
- The **signature** is bytes(x(R)) || bytes(s).

## References

Provably Secure Distributed Schnorr Signatures and a (t, n) Threshold Scheme for Implicit Certificates<br>
http://cacr.uwaterloo.ca/techreports/2001/corr2001-13.ps


## Acknowledgements

I would like to thank everyone who advised.
