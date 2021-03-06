# js-crypto

Crypto library - works both in node and in the browsers.

This library contains all we need for cryptography in javascript in a browser-compatible way.
All keys and signatures should also be compatible with [go-crypto](https://github.com/stratumn/go-crypto). We keep adding and making changes to it, so use it at your own risk. Stratumn will not be responsible for any issue that may arise if you use it in your systems.

**REQUIREMENT**: Your platform should support Uint8Array for this library to work correctly. See https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array#Browser_compatibility

---

## **Signatures**

The signatures module is in js-crypto/sig
The currently supported algos are:

- RSA
- ED25519

Signatures are object containing:

- signature: the base64 encoding of the PEM encoded signature
- public_key: the base64 encoding of the PEM encoded public key
- message: the base64 encoded message

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

You can then use the private key to sign a Uint8Array message:

```javascript
import { utils } from '@stratumn/js-crypto';

const msgBytes = utils.stringToBytes('some message');
const signature = key.sign(msgBytes);

// signature is a protobuf object. You can serialize it by doing:
const serializedSignature = utils.signatureToJson(signature);
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

The public key is used to verify a signature. The signature and message fields of the verify method should be Uint8Arrays.

```javascript
import { utils } from '@stratumn/js-crypto';

// The sigObj is the output of the sign method
const serializedSignature = {
  signature: 'deadbeef',
  message: '123456',
  public_key: 'ba5e64'
};

const sig = utils.signatureFromJson(serializedSignature);

// sig = {
//  signature: Uint8Array{},
//  message: Uint8Array{},
//  public_key: Uint8Array{}
// }

// Verify the signature
const ok = key.verify(sig);
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
const message = key.decrypt(ciphertext);
```

where ciphertext is a string containing the encrypted message and the decryption options.

The ciphertext is the result of the encryption (see below).

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
const ciphertext = key.encrypt('some text message');
```

## Release process

We are using `semantic-release` to publish the package on the NPM registry. Publishing can be triggered by "promoting" a successful build on master from Semaphore UI.
The commit message summary should follow the following format:

`Tag: Message (fixes #1234)`

Where `Tag` is one of the following:

- Fix - for a bug fix. (patch)
- Update - for a backwards-compatible enhancement. (minor)
- New - implemented a new feature. (minor)
- Breaking - for a backwards-incompatible enhancement. (major)

The message summary should be a one-sentence description of the change. The issue number should be mentioned at the end. \* The commit message should say "(fixes #1234)" at the end of the description if it closes out an existing issue (replace 1234 with the issue number). If the commit doesn't completely fix the issue, then use (refs #1234) instead of (fixes #1234).

Here are some good commit message summary examples:

```

Build: Update Semaphore to only test Node 0.10 (refs #734)
Fix: Semi rule incorrectly flagging extra semicolon (fixes #840)
Upgrade: Express to 13.4.2, switch to using Express comment attachment (fixes #730)

```
