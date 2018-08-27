# js-crypto

Browser compatible crypto lib

**DISCLAIMER**: THIS LIBRARY IS FAR FROM BEING PROD READY, USE IT AT YOUR OWN RISK.

This library contains all what we need for cryptography in javascript in a browser compatible way.
All keys and signatures should also be compatible with [go-crypto](https://github.com/stratumn/go-crypto).

---

## **Signatures**

The signatures module is in js-crypto/sig
The currently supported algos are:

- RSA
- ED25519

### Private key

Private keys are PKCE#8 embedded and PEM encoded. They can be encrypted using PKCS#5.

One can either generate a new key with:

```javascript
import {
  sig,
  SIGNING_ALGO_RSA,
  SIGNING_ALGO_ED25519
} from '@stratumn/js-cryto';

// A new RSA key.
const key = new sig.SigningPrivateKey({ algo: SIGNING_ALGO_RSA.name });

// A new ED25519 key.
const key = new sig.SigningPrivateKey({ algo: SIGNING_ALGO_ED25519.name });
```

or import an existing one with:

```javascript
import { sig } from '@stratumn/js-cryto';

// A PEM encoded private key embedded in PKCS#8.
const pemKey =
  '-----BEGIN RSA PRIVATE KEY-----......-----END RSA PRIVATE KEY-----';
const key = new sig.SigningPrivateKey({ pemPrivateKey: pemKey });

// A PEM encoded encrypted private key embedded in PKCS#8.
const pemKey =
  '-----BEGIN ENCRYPTED PRIVATE KEY-----......-----END ENCRYPTED PRIVATE KEY-----';
const key = new sig.SigningPrivateKey({
  pemPrivateKey: pemKey,
  password: 'some password'
});
```

and then use that key to sign a message:

```javascript
const signature = key.sign('some message');
```

The private key can be exported by doing

```javascript
// the PEM encoding of the private key embedded in PKCS#8
const pemKey = key.export();

// the PEM encoding of the encrypted private key embedded in PKCS#8
const pemKey = key.export('some password');
```

The public key is obtained by doing

```javascript
const publicKey = key.publicKey();
```

### Public key

Public keys can be loaded either from a PEM encoded key.

```javascript
import { sig } from '@stratumn/js-crypto';

const pemKey =
  '-----BEGIN RSA PUBLIC KEY-----......-----END RSA PUBLIC KEY-----';
const key = new sig.SigningPublicKey({ pemPublicKey: pemKey });
```

The public key is used to verify a signature:

```javascript
const sig = '-----BEGIN MESSAGE-----...';
const ok = key.verify({ message: 'some message', signature: sig });
```

---

## **Public Key Encryption**

The currently supported algos are:

- RSA-OAEP + AES-GCM

### Private key

Private keys are PKCE#8 embedded and PEM encoded. They can be encrypted using PKCS#5.

One can either generate a new key with:

```javascript
import { pke, PKE_ALGO_RSA } from '@stratumn/js-cryto';

// A new RSA key.
const key = new pke.EncryptionPrivateKey({ algo: PKE_ALGO_RSA.name });
```

or import an existing one with:

```javascript
import { pke } from '@stratumn/js-cryto';

// A PEM encoded private key embedded in PKCS#8.
const pemKey =
  '-----BEGIN RSA PRIVATE KEY-----......-----END RSA PRIVATE KEY-----';
const key = new pke.EncryptionPrivateKey({ pemPrivateKey: pemKey });

// A PEM encoded encrypted private key embedded in PKCS#8.
const pemKey =
  '-----BEGIN ENCRYPTED PRIVATE KEY-----......-----END ENCRYPTED PRIVATE KEY-----';
const key = new pke.EncryptionPrivateKey({
  pemPrivateKey: pemKey,
  password: 'some password'
});
```

and then use that key to decrypt a message:

```javascript
const message = key.decrypt('ciphertext', opts);
```

where opts is an object containing the decryption options. For example, in the case of RSA + AES-GCM, opts contain:

- encryptedAESKey: the encryption of the symmetric key
- iv: the initialization vector
- tag: the authentication tag

The decryption opptions are supposed to be returned by the encryption (see below).

The private key can be exported by doing

```javascript
// the PEM encoding of the private key embedded in PKCS#8
const pemKey = key.export();

// the PEM encoding of the encrypted private key embedded in PKCS#8
const pemKey = key.export('some password');
```

The public key is obtained by doing

```javascript
const publicKey = key.publicKey();
```

### Public key

Public keys can be loaded either from a PEM encoded key.

```javascript
import { pke } from '@stratumn/js-crypto';

const pemKey =
  '-----BEGIN RSA PUBLIC KEY-----......-----END RSA PUBLIC KEY-----';
const key = new pke.EncryptionPublicKey({ pemPublicKey: pemKey });
```

The public key is used to encrypt a message:

```javascript
const { ciphertext, opts...} = key.encrypt('some text message');
```
