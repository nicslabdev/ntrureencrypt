# NTRUReEncrypt - Prototype implementation in Java

## Summary
This repository contains a prototype implementation of NTRUReEncrypt, a Proxy Re-Encryption scheme based on NTRU, proposed by Nuñez, Agudo and 
Lopez, in ACM AsiaCCS 2015 [1].

This proxy re-encryption scheme extends the conventional NTRU scheme, adding functions to re-encrypt ciphertexts and to generate re-encryption keys.

This prototype implementation is built upon the NTRU implementation in [tbuktu/ntru](https://github.com/tbuktu/ntru), version 1.2. Note that this 
prototype is a mere proof of concept so the implementation is completely monolithic. Modularization and refactoring is WIP.

## Tested with

- java compiler 17.0.10
- maven 3.6.3

## Instalation

`$ git clone https://github.com/nicslabdev/ntrureencrypt.git`
`$ cd ntrureencrypt`
`$ mvn clean package`

## Project structure

- **NTRUReEncryptParams** - A wrapper of the parameter sets from [tbuktu/ntru](https://github.com/tbuktu/ntru) that allow handling parameters outside of the original class.
- **NTRUReEncrypt** - The main class that enable to generate keys, encrypt, re-encrypt, and decrypt. It also provides encoding/decoding functions for the messages.
- **ReEncryptionKey** - A class to handle a re-encryption key.
- **Utils** - Functions for data representation conversions.
- **TestNTRUReEncrypt** - Test class.

## Usage example

```
// Parameter instance
byte[] seed = new byte[]{0,1,2};
EncryptionParameters params = NTRUReEncryptParams.getParams("EES1087EP2_FAST");
int dm0 = NTRUReEncryptParams.getDM0("EES1087EP2_FAST");

// NTRU object and key generation
NTRUReEncrypt ntruReEnc = new NTRUReEncrypt(params);
EncryptionKeyPair kpA = ntruReEnc.generateKeyPair();
EncryptionKeyPair kpB = ntruReEnc.generateKeyPair();
ReEncryptionKey rk = ntruReEnc.generateReEncryptionKey(kpA, kpB);

// Random message generation
int mLen = 128;
Random rng = new Random(12345);
BigInteger m = new BigInteger(mLen, rng);

// Encoding and encryption
IntegerPolynomial M = ntruReEnc.encodeMessage(m, seed, dm0);
IntegerPolynomial CA = ntruReEnc.encrypt(kpA.getPublic(), M, seed);

// Re-Encryption
IntegerPolynomial CB = ntruReEnc.reEncrypt(rk, CA, seed);

// Decryption and decoding
IntegerPolynomial D = ntruReEnc.decrypt(kpB.getPrivate(), CB);
BigInteger d = ntruReEnc.decodeMessagetoBigInteger(D, mLen);
```

## NTRU as an Additively Homomorphic Encryption scheme

### Basic property

NTRU is an Additively Homomorphic Encryption (AHE) scheme by definition.

Given the public key $$h$$, two randomly sampled polynomials $$s_1, s_2$$ with small coefficients, and two messages $$M_1, M_2$$ encoded as ternary polynomials, then
$$C_1 = h \cdot s_1 + M_1 (mod\;q)$$
$$C_2 = h \cdot s_2 + M_2 (mod\;q)$$
$$C_3 = C_1 + C_2 = h \cdot (s_1 + s_2) + (M_1 + M_2) (mod\;q)$$
It can be noticed by correctness that $$Dec(C_3) = (M_1 + M_2)$$ as long as $$(s_1 + s_2)$$ remains small enough.

### Addition of integers mod q

It can be noticed that in the base scheme, each message is encoded as a polynomial. Therefore, $$(M_1 + M_2)$$ is the addition of two polynomials, which is not directly translated to the addition of the original integer messages $$(m_1 + m_2)$$.

To tackle this issue, we propose a special codification that allows to perform a single addition of two ciphertexts such that they can be decoded to the sum of integers. The process is as follows:

- **Encoding** - Since an NTRU message is a polynomial with ternary coefficients, i.e., from the set {-1, 0, 1}, given B the binary representation of m, we let the coefficient with degree k to encode the digit B[k]. Note that they will all be 0s and 1s, so there must remain enough free coefficients in the polynomial to guarantee a minimum number dm0 of coefficients with each value in {-1, 0, 1}.
- **Decoding** - Since messages are ternary polynomials, they can be added bit by bit (coefficient by coefficient) such that if there is a carry to perform, the resultant coefficient will be -1. This addition is done inside the ciphertext space. Once decrypted, all the carries are applied by the decoding algorithm from the LSB to the MSB.

## Further reading
[1] Nuñez, D., Agudo, I., & Lopez, J. (2015). NTRUReEncrypt: An efficient proxy re-encryption scheme based on NTRU. In Proceedings of the 10th ACM 
Symposium on Information, Computer and Communications Security (pp. 179-189). ACM. 
([link](https://www.nics.uma.es/wp-content/papers/nunez2015ntrureencrypt.pdf))