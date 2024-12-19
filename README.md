# Let's Decrypt!

A TypeScript library for encryption and key management, compatible with both Node.js and browsers. It provides a simple interface for generating key pairs, encrypting, and decrypting data using various algorithms including RSA, ECC, and AES.

## Features

- 🔑 Multiple cryptographic algorithms support (RSA, ECC, AES)
- 🔒 Passphrase protection for private keys
- 💻 Cross-platform compatibility (Node.js and Browser)
- 🔄 Key pair generation and management
- 📦 Serializable keys and encrypted data
- 🛡️ Built on top of the Web Crypto API
  
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


## License

MIT License

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
