# Let's Decrypt!

A TypeScript library for encryption and key management, compatible with both Node.js and browsers. 

It leverages the **Web Crypto API** and provides a simple interface for **generating key pairs**, **encrypting**, and **decrypting** data using various algorithms including **RSA**, **ECC**, and **AES**.

Public / private keys and secrets can be **serialized** for storage.

## Features

- 🔑 Multiple cryptographic algorithms support (RSA, ECC, AES)
- 🔒 Passphrase protection for private keys
- 💻 Cross-platform compatibility (Node.js and Browser)
- 🔄 Key pair generation and management
- 📦 Serializable keys and encrypted data
- 🛡️ Built on top of the Web Crypto API

## Playground

You can test the library in your browser using the [Let's Decrypt Playground](https://letsdecrypt.pages.dev/).

## Prerequisites

You can run this library in both Node.js and browser environments.
The following are the minimum versions required for each:

### NodeJS
- Node.js >= 15.0.0 (for the Web Crypto API support)

### Browser
- Chrome 37+
- Firefox 34+
- Safari 7+
- Edge 12+

## Installation

```bash
npm install letsdecrypt
```

## Usage

### Basic Example

```typescript
import { generateKeyPair, encrypt, decrypt } from 'letsdecrypt';

async function example() {
  // Generate a key pair (defaults to RSA)
  const keyPair = await generateKeyPair();

  // Encrypt some data
  const message = "Hello, World!";
  const encrypted = await encrypt(message, keyPair.publicKey);

  // Decrypt the data
  const decrypted = await decrypt(encrypted, keyPair.privateKey);
  console.log(decrypted); // "Hello, World!"
}
```

### Changing Private Key Passphrase

```typescript
import { changePassphrase } from 'letsdecrypt';

// Change the passphrase protecting a private key
const newPrivateKey = await changePassphrase(
  existingPrivateKey,
  'old-passphrase',
  'new-passphrase'
);
```


### Key Pair Generation with Options

```typescript
// RSA with custom modulus length
const rsaKeyPair = await generateKeyPair({
  algorithm: 'RSA',
  rsaModulusLength: 4096 // Other values: 2048, 3072
});

// ECC with specific curve
const eccKeyPair = await generateKeyPair({
  algorithm: 'ECC',
  eccCurve: 'P-256' // Other values: 'P-384', 'P-521'
});

// AES key pair (public key and private key will actually be the same)
const aesKeyPair = await generateKeyPair({
  algorithm: 'AES'
});

// Protected key pair with passphrase
const protectedKeyPair = await generateKeyPair({
  algorithm: 'RSA',
  passphrase: 'My p4sphr4s3 1s v3ry 5ecur3d!'
});
```

### Exporting and Importing Keys

```typescript
import { generateKeyPair, exportKeyPair, encrypt, decrypt } from 'letsdecrypt';

async function keyManagement() {
  // Generate and export keys
  const keyPair = await generateKeyPair();
  const {publicKey, privateKey} = await exportKeyPair(keyPair);

  // Store keys safely (theoretically, store the private key apart from the public key)
  localStorage.setItem('keys', JSON.stringify({publicKey, privateKey}));

  // Later, import and use the keys
  const storedKeys = JSON.parse(localStorage.getItem('keys'));
  const encrypted = await encrypt("Secret message", storedKeys.publicKey);
  const decrypted = await decrypt(encrypted, storedKeys.privateKey);
}
```

## API Reference

### Functions

#### `generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair>`

Generates a new key pair based on the specified options.

Options:
- `algorithm?: 'RSA' | 'ECC' | 'AES'` - The cryptographic algorithm to use (default: 'RSA')
- `passphrase?: string` - Optional passphrase to protect the private key
- `rsaModulusLength?: number` - RSA key length in bits (default: 2048)
- `eccCurve?: 'P-256' | 'P-384' | 'P-521'` - ECC curve to use (default: 'P-256')

#### `encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret>`

Encrypts data using the provided public key.

Parameters:
- `data: string` - The data to encrypt
- `publicKey: MaybeSerializedKey` - The public key (can be serialized or CryptoKey)

#### `decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string>`

Decrypts data using the provided private key.

Parameters:
- `secret: Secret | string` - The encrypted data
- `privateKey: MaybeSerializedKey` - The private key (can be serialized or CryptoKey)
- `passphrase?: string` - Required if the private key is protected

#### `changePassphrase(privateKey: MaybeSerializedKey, oldPassphrase: string, newPassphrase: string): Promise<WrappedKeyData>`

Changes the passphrase protecting a private key.

Parameters:
- `privateKey: MaybeSerializedKey` - The private key to re-protect
- `oldPassphrase: string` - Current passphrase protecting the key
- `newPassphrase: string` - New passphrase to protect the key with

#### `exportKeyPair(keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair>`

Exports a key pair to a serializable format.

Parameters:
- `keyPair: CryptoKeyPair | WrappedCryptoKeyPair` - The key pair to export

### Types

```typescript
interface KeyPairOptions {
  passphrase?: string;
  algorithm?: 'RSA' | 'ECC' | 'AES';
  rsaModulusLength?: number;
  eccCurve?: 'P-256' | 'P-384' | 'P-521';
}

interface SerializedKeyPair {
  publicKey: string;
  privateKey: string;
}

interface Secret {
  encryptedData: string;
  metadata: {
    algorithm: string;
    keyHash: string;
    symmetricKey?: string;
    iv?: string;
    publicKey?: string;
    namedCurve?: string;
  };
}
```

## Security Considerations

1. Always store private keys securely and never expose them in client-side code
2. Use strong passphrases when protecting private keys
3. The library uses secure defaults but allows customization for specific needs
4. All cryptographic operations are performed using the Web Crypto API

## Algorithm Selection Guide

### RSA (Default)
Best for:
- Public key infrastructure (PKI)
- Digital signatures
- Secure key exchange
- Scenarios where keys are generated once and used multiple times

Configuration options:
```typescript
const keyPair = await generateKeyPair({
  algorithm: 'RSA',
  rsaModulusLength: 2048 // or 4096 for higher security
});
```

Considerations:
- Slower than ECC for equivalent security levels
- Larger key sizes (2048/4096 bits)
- Well-established and widely supported
- rsaModulusLength:
    - 2048 bits: Standard security (default, recommended for most uses)
    - 4096 bits: Higher security, but slower operations

### ECC (Elliptic Curve Cryptography)
Best for:
- Mobile and IoT applications
- Resource-constrained environments
- Scenarios requiring high performance
- Modern applications without legacy compatibility requirements

Configuration options:
```typescript
const keyPair = await generateKeyPair({
  algorithm: 'ECC',
  eccCurve: 'P-256' // or 'P-384', 'P-521'
});
```

Considerations:
- Faster than RSA with smaller key sizes
- Excellent security-to-performance ratio
- Not as widely supported as RSA
- eccCurve options:
    - P-256: Standard security (recommended for most uses)
    - P-384: Higher security
    - P-521: Maximum security, but slower operations

### AES (Advanced Encryption Standard)
Best for:
- Symmetric encryption scenarios
- High-performance encryption of large data
- Scenarios where both parties can securely share the key
- Stream processing of data

Configuration options:
```typescript
const keyPair = await generateKeyPair({
  algorithm: 'AES'
});
```

Considerations:
- Fastest encryption/decryption performance
- Requires secure key exchange
- Same key for encryption and decryption
- Fixed 256-bit key size
- Best used in combination with RSA or ECC for key exchange

### General Recommendations

1. For general-purpose public key encryption:
    - Use RSA with 2048-bit keys (default)
   ```typescript
   const keyPair = await generateKeyPair(); // Uses RSA by default
   ```

2. For modern, high-performance applications:
    - Use ECC with P-256 curve
   ```typescript
   const keyPair = await generateKeyPair({
     algorithm: 'ECC',
     eccCurve: 'P-256'
   });
   ```

3. For maximum security:
    - Use RSA with 4096-bit keys or ECC with P-521 curve
   ```typescript
   // Option 1: RSA 4096
   const keyPair = await generateKeyPair({
     algorithm: 'RSA',
     rsaModulusLength: 4096
   });
   
   // Option 2: ECC P-521
   const keyPair = await generateKeyPair({
     algorithm: 'ECC',
     eccCurve: 'P-521'
   });
   ```

4. For key protection:
    - Always use a strong passphrase for sensitive keys
   ```typescript
   const keyPair = await generateKeyPair({
     algorithm: 'RSA', // or 'ECC'
     passphrase: 'your-strong-passphrase'
   });
   ```

### Performance Considerations

Algorithm | Key Generation | Encryption | Decryption | Key Size | Security Level
----------|---------------|------------|------------|-----------|---------------
RSA-2048  | Slow         | Fast       | Moderate   | 2048 bits | Standard
RSA-4096  | Very Slow    | Fast       | Slow       | 4096 bits | High
ECC P-256 | Fast         | Fast       | Fast       | 256 bits  | Standard
ECC P-521 | Fast         | Moderate   | Moderate   | 521 bits  | Very High
AES-256   | Very Fast    | Very Fast  | Very Fast  | 256 bits  | High


## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
