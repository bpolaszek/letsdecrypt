import { Buffer } from 'buffer';

export interface KeyPairOptions {
  passphrase?: string;
  algorithm?: 'RSA' | 'ECC';
  rsaModulusLength?: number;
  eccCurve?: 'P-256' | 'P-384' | 'P-521';
}

export interface SerializedKeyPair {
  publicKey: string;
  privateKey: string;
}

export interface SecretMetadata {
  algorithm: string;
  keyHash: string;
  iv: string;
  symmetricKey: string;
  publicKey?: string; // For ECC, we need to store the ephemeral public key
}

export interface WrappedKeyData {
  wrappedKey: string; // base64 encoded
  iv: string; // base64 encoded
  algorithm: string; // The algorithm used for the key
  format: string; // The format of the wrapped key
}

export interface CryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
}

export interface WrappedCryptoKeyPair {
  publicKey: CryptoKey;
  privateKey: WrappedKeyData;
}

export class Secret {
  private encryptedData: string;
  private metadata: SecretMetadata;

  constructor(encryptedData: string, metadata: SecretMetadata) {
    this.encryptedData = encryptedData;
    this.metadata = metadata;
  }

  serialize(): string {
    return JSON.stringify({
      data: this.encryptedData,
      metadata: this.metadata,
    });
  }

  static deserialize(serialized: string): Secret {
    const parsed = JSON.parse(serialized);
    return new Secret(parsed.data, parsed.metadata);
  }

  getEncryptedData(): string {
    return this.encryptedData;
  }

  getMetadata(): SecretMetadata {
    return this.metadata;
  }
}

export class CryptoService {
  private static readonly RSA_ALGORITHM = 'RSA-OAEP';
  private static readonly ECC_ALGORITHM = 'ECDH';
  private static readonly SYMMETRIC_ALGORITHM = 'AES-GCM';
  private static readonly WRAP_ALGORITHM = 'AES-KW';
  private static readonly DEFAULT_RSA_LENGTH = 2048;
  private static readonly DEFAULT_ECC_CURVE = 'P-256';
  private static readonly HASH = 'SHA-256';

  private static getKeyGenParams(options?: KeyPairOptions): RsaHashedKeyGenParams | EcKeyGenParams {
    const algorithm = options?.algorithm || 'RSA';

    if (algorithm === 'RSA') {
      return {
        name: this.RSA_ALGORITHM,
        modulusLength: options?.rsaModulusLength || this.DEFAULT_RSA_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: this.HASH,
      };
    } else {
      return {
        name: this.ECC_ALGORITHM,
        namedCurve: options?.eccCurve || this.DEFAULT_ECC_CURVE,
      };
    }
  }

  private static getPublicKeyUsages(algorithm: string): KeyUsage[] {
    if (algorithm === this.RSA_ALGORITHM) {
      return ['encrypt'];
    } else if (algorithm === this.ECC_ALGORITHM) {
      return [];  // Public keys in ECDH don't need any usages
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  private static getPrivateKeyUsages(algorithm: string): KeyUsage[] {
    if (algorithm === this.RSA_ALGORITHM) {
      return ['decrypt'];
    } else if (algorithm === this.ECC_ALGORITHM) {
      return ['deriveKey', 'deriveBits'];
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  private static getKeyPairUsages(algorithm: string): KeyUsage[] {
    if (algorithm === this.RSA_ALGORITHM) {
      return ['encrypt', 'decrypt'];
    } else if (algorithm === this.ECC_ALGORITHM) {
      return ['deriveKey', 'deriveBits'];
    } else {
      throw new Error(`Unsupported algorithm: ${algorithm}`);
    }
  }

  static async generateKeyPair(options?: KeyPairOptions): Promise<CryptoKeyPair | WrappedCryptoKeyPair> {
    const params = this.getKeyGenParams(options);
    const keyPair = await crypto.subtle.generateKey(
      params,
      true,
      this.getKeyPairUsages(params.name)
    );

    if (options?.passphrase) {
      // If passphrase provided, wrap the private key
      const wrappedPrivateKey = await this.wrapKey(keyPair.privateKey, options.passphrase, params.name);
      return {
        publicKey: keyPair.publicKey,
        privateKey: wrappedPrivateKey,
      };
    }

    return keyPair;
  }

  static async exportKeyPair(keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> {
    if ('privateKey' in keyPair && 'wrappedKey' in keyPair.privateKey) {
      const exportedPublic = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      return {
        publicKey: Buffer.from(exportedPublic).toString('base64'),
        privateKey: JSON.stringify(keyPair.privateKey),
      };
    } else {
      const exportedPublic = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      const exportedPrivate = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);

      return {
        publicKey: Buffer.from(exportedPublic).toString('base64'),
        privateKey: Buffer.from(exportedPrivate).toString('base64'),
      };
    }
  }

  static async importPublicKey(serialized: string): Promise<CryptoKey> {
    const binaryKey = Buffer.from(serialized, 'base64');

    try {
      // Try RSA first
      return await crypto.subtle.importKey(
        'spki',
        binaryKey,
        {
          name: this.RSA_ALGORITHM,
          hash: this.HASH,
        },
        true,
        this.getPublicKeyUsages(this.RSA_ALGORITHM)
      );
    } catch {
      // If RSA fails, try ECC
      return await crypto.subtle.importKey(
        'spki',
        binaryKey,
        {
          name: this.ECC_ALGORITHM,
          namedCurve: this.DEFAULT_ECC_CURVE,
        },
        true,
        this.getPublicKeyUsages(this.ECC_ALGORITHM)
      );
    }
  }

  static async importPrivateKey(
    serialized: string,
    passphrase?: string
  ): Promise<CryptoKey> {
    if (serialized.startsWith('{')) {
      const wrappedKeyData: WrappedKeyData = JSON.parse(serialized);
      return this.unwrapKey(wrappedKeyData, passphrase);
    } else {
      const binaryKey = Buffer.from(serialized, 'base64');
      try {
        // Try RSA first
        const key = await crypto.subtle.importKey(
          'pkcs8',
          binaryKey,
          {
            name: this.RSA_ALGORITHM,
            hash: this.HASH,
          },
          true,
          this.getPrivateKeyUsages(this.RSA_ALGORITHM)
        );

        if (passphrase) {
          return this.unwrapKey(key, passphrase);
        }

        return key;
      } catch {
        // If RSA fails, try ECC
        const key = await crypto.subtle.importKey(
          'pkcs8',
          binaryKey,
          {
            name: this.ECC_ALGORITHM,
            namedCurve: this.DEFAULT_ECC_CURVE,
          },
          true,
          this.getPrivateKeyUsages(this.ECC_ALGORITHM)
        );

        if (passphrase) {
          return this.unwrapKey(key, passphrase);
        }

        return key;
      }
    }
  }

  static async encrypt(
    data: string,
    publicKey: CryptoKey | string
  ): Promise<Secret> {
    const key = typeof publicKey === 'string'
      ? await this.importPublicKey(publicKey)
      : publicKey;

    // Get the algorithm from the key
    const keyAlgorithm = key.algorithm as EcKeyImportParams | RsaHashedImportParams;
    const algorithm = keyAlgorithm.name === this.ECC_ALGORITHM ? this.ECC_ALGORITHM : this.RSA_ALGORITHM;

    if (algorithm === this.ECC_ALGORITHM) {
      // For ECC, we need to:
      // 1. Generate an ephemeral key pair
      // 2. Derive a shared secret using ECDH
      // 3. Use the shared secret to encrypt the data
      const ephemeralKeyPair = await crypto.subtle.generateKey(
        {
          name: this.ECC_ALGORITHM,
          namedCurve: (keyAlgorithm as EcKeyImportParams).namedCurve,
        },
        true,
        ['deriveKey', 'deriveBits']
      ) as CryptoKeyPair;

      // Derive the shared secret
      const sharedSecret = await crypto.subtle.deriveKey(
        {
          name: this.ECC_ALGORITHM,
          public: key,
        },
        ephemeralKeyPair.privateKey,
        {
          name: this.SYMMETRIC_ALGORITHM,
          length: 256
        },
        false,
        ['encrypt']
      );

      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt the data with the derived key
      const encodedData = new TextEncoder().encode(data);
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: this.SYMMETRIC_ALGORITHM,
          iv,
        },
        sharedSecret,
        encodedData
      );

      // Export the ephemeral public key - we'll need it for decryption
      const exportedEphemeralKey = await crypto.subtle.exportKey('spki', ephemeralKeyPair.publicKey);

      // Create metadata
      const metadata: SecretMetadata = {
        algorithm: this.ECC_ALGORITHM,
        keyHash: await this.hashKey(key),
        iv: Buffer.from(iv).toString('base64'),
        symmetricKey: '', // Not needed for ECC
        publicKey: Buffer.from(exportedEphemeralKey).toString('base64')
      };

      return new Secret(
        Buffer.from(encryptedData).toString('base64'),
        metadata
      );
    } else {
      // RSA encryption path (unchanged)
      // Generate a symmetric key for the actual data encryption
      const symmetricKey = await crypto.subtle.generateKey(
        {
          name: this.SYMMETRIC_ALGORITHM,
          length: 256,
        },
        true,
        ['encrypt', 'decrypt']
      );

      // Generate IV
      const iv = crypto.getRandomValues(new Uint8Array(12));

      // Encrypt the data with the symmetric key
      const encodedData = new TextEncoder().encode(data);
      const encryptedData = await crypto.subtle.encrypt(
        {
          name: this.SYMMETRIC_ALGORITHM,
          iv,
        },
        symmetricKey,
        encodedData
      );

      // Export and encrypt the symmetric key with the public key
      const exportedSymKey = await crypto.subtle.exportKey('raw', symmetricKey);
      const encryptedSymKey = await crypto.subtle.encrypt(
        {
          name: this.RSA_ALGORITHM,
        },
        key,
        exportedSymKey
      );

      // Create metadata
      const metadata: SecretMetadata = {
        algorithm: this.RSA_ALGORITHM,
        keyHash: await this.hashKey(key),
        iv: Buffer.from(iv).toString('base64'),
        symmetricKey: Buffer.from(encryptedSymKey).toString('base64')
      };

      return new Secret(
        Buffer.from(encryptedData).toString('base64'),
        metadata
      );
    }
  }

  static async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string
  ): Promise<string> {
    const secretObj = typeof secret === 'string' ? Secret.deserialize(secret) : secret;
    let key: CryptoKey;

    if (typeof privateKey === 'string') {
      key = await this.importPrivateKey(privateKey, passphrase);
    } else if ('wrappedKey' in privateKey) {
      key = await this.unwrapKey(privateKey, passphrase);
    } else {
      key = privateKey;
    }

    const metadata = secretObj.getMetadata();
    if (metadata.algorithm === this.ECC_ALGORITHM) {
      // Import the ephemeral public key
      const ephemeralPublicKey = await crypto.subtle.importKey(
        'spki',
        Buffer.from(metadata.publicKey, 'base64'),
        {
          name: this.ECC_ALGORITHM,
          namedCurve: this.DEFAULT_ECC_CURVE,
        },
        true,
        []
      );

      // Derive the same shared secret
      const sharedSecret = await crypto.subtle.deriveKey(
        {
          name: this.ECC_ALGORITHM,
          public: ephemeralPublicKey,
        },
        key,
        {
          name: this.SYMMETRIC_ALGORITHM,
          length: 256
        },
        false,
        ['decrypt']
      );

      // Decrypt the data
      const encryptedData = Buffer.from(secretObj.getEncryptedData(), 'base64');
      const iv = Buffer.from(metadata.iv, 'base64');

      const decryptedData = await crypto.subtle.decrypt(
        {
          name: this.SYMMETRIC_ALGORITHM,
          iv,
        },
        sharedSecret,
        encryptedData
      );

      return new TextDecoder().decode(decryptedData);
    } else {
      // RSA decryption path (unchanged)
      // Decrypt the symmetric key
      const encryptedSymKey = Buffer.from(metadata.symmetricKey, 'base64');
      const symmetricKeyBuffer = await crypto.subtle.decrypt(
        {
          name: this.RSA_ALGORITHM,
        },
        key,
        encryptedSymKey
      );

      // Import the symmetric key
      const symmetricKey = await crypto.subtle.importKey(
        'raw',
        symmetricKeyBuffer,
        {
          name: this.SYMMETRIC_ALGORITHM,
          length: 256,
        },
        false,
        ['decrypt']
      );

      // Decrypt the data
      const encryptedData = Buffer.from(secretObj.getEncryptedData(), 'base64');
      const iv = Buffer.from(metadata.iv, 'base64');

      const decryptedData = await crypto.subtle.decrypt(
        {
          name: this.SYMMETRIC_ALGORITHM,
          iv,
        },
        symmetricKey,
        encryptedData
      );

      return new TextDecoder().decode(decryptedData);
    }
  }

  private static async wrapKey(
    key: CryptoKey,
    passphrase: string,
    algorithm: string
  ): Promise<WrappedKeyData> {
    // First export the private key to wrap it
    const format = algorithm === this.ECC_ALGORITHM ? 'jwk' : 'pkcs8';
    const keyData = await crypto.subtle.exportKey(format, key);
    const keyBytes = format === 'jwk' ?
      new TextEncoder().encode(JSON.stringify(keyData)) :
      new Uint8Array(keyData);

    // Generate a wrapping key from the passphrase
    const wrappingKey = await this.generateKeyFromPassphrase(passphrase);

    // Generate IV for encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));

    // Wrap the exported key data
    const wrapped = await crypto.subtle.encrypt(
      { name: this.SYMMETRIC_ALGORITHM, iv },
      wrappingKey,
      keyBytes
    );

    // Return the wrapped key data in base64 format with format information
    return {
      wrappedKey: Buffer.from(wrapped).toString('base64'),
      iv: Buffer.from(iv).toString('base64'),
      algorithm,
      format // Add format information
    };
  }

  private static async unwrapKey(
    wrappedData: WrappedKeyData,
    passphrase: string
  ): Promise<CryptoKey> {
    // Generate the unwrapping key from the passphrase
    const unwrappingKey = await this.generateKeyFromPassphrase(passphrase);

    // Decode the wrapped key and IV from base64
    const wrappedKey = Buffer.from(wrappedData.wrappedKey, 'base64');
    const iv = Buffer.from(wrappedData.iv, 'base64');

    // Decrypt the wrapped key
    const unwrappedData = await crypto.subtle.decrypt(
      { name: this.SYMMETRIC_ALGORITHM, iv },
      unwrappingKey,
      wrappedKey
    );

    // Handle the unwrapped data based on the original format
    const format = (wrappedData as any).format || (wrappedData.algorithm === this.ECC_ALGORITHM ? 'jwk' : 'pkcs8');
    const keyData = format === 'jwk' ?
      JSON.parse(new TextDecoder().decode(unwrappedData)) :
      unwrappedData;

    // Import the key with the correct algorithm parameters
    const importParams = wrappedData.algorithm === this.ECC_ALGORITHM ?
      { name: this.ECC_ALGORITHM, namedCurve: this.DEFAULT_ECC_CURVE } :
      { name: this.RSA_ALGORITHM, hash: this.HASH };

    return crypto.subtle.importKey(
      format,
      keyData,
      importParams,
      true,
      this.getPrivateKeyUsages(wrappedData.algorithm)
    );
  }

  private static async generateKeyFromPassphrase(
    passphrase: string
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt: encoder.encode('salt'),
        iterations: 100000,
        hash: this.HASH,
      },
      keyMaterial,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256,
      },
      true,
      ['encrypt', 'decrypt']
    );
  }

  private static async hashKey(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key);
    const hashBuffer = await crypto.subtle.digest(this.HASH, exported);
    return Buffer.from(hashBuffer).toString('hex');
  }
}
