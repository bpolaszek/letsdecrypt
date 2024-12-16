import { Buffer } from 'buffer';

export interface KeyPairOptions {
  passphrase?: string;
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
}

export interface WrappedKeyData {
  wrappedKey: string; // base64 encoded
  iv: string; // base64 encoded
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
  private static readonly ALGORITHM = 'RSA-OAEP';
  private static readonly SYMMETRIC_ALGORITHM = 'AES-GCM';
  private static readonly WRAP_ALGORITHM = 'AES-KW';
  private static readonly KEY_LENGTH = 2048;
  private static readonly HASH = 'SHA-256';

  static async generateKeyPair(options?: KeyPairOptions): Promise<CryptoKeyPair | WrappedCryptoKeyPair> {
    const keyPair = await crypto.subtle.generateKey(
      {
        name: this.ALGORITHM,
        modulusLength: this.KEY_LENGTH,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: this.HASH,
      },
      true,
      ['encrypt', 'decrypt']
    );

    if (options?.passphrase) {
      // If passphrase provided, wrap the private key
      const wrappedPrivateKey = await this.wrapKey(keyPair.privateKey, options.passphrase);
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
    return crypto.subtle.importKey(
      'spki',
      binaryKey,
      {
        name: this.ALGORITHM,
        hash: this.HASH,
      },
      true,
      ['encrypt']
    );
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
      const key = await crypto.subtle.importKey(
        'pkcs8',
        binaryKey,
        {
          name: this.ALGORITHM,
          hash: this.HASH,
        },
        true,
        ['decrypt']
      );

      if (passphrase) {
        return this.unwrapKey(key, passphrase);
      }

      return key;
    }
  }

  static async encrypt(
    data: string,
    publicKey: CryptoKey | string
  ): Promise<Secret> {
    const key = typeof publicKey === 'string' 
      ? await this.importPublicKey(publicKey)
      : publicKey;

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
        name: this.ALGORITHM,
      },
      key,
      exportedSymKey
    );

    // Create metadata
    const metadata: SecretMetadata = {
      algorithm: this.ALGORITHM,
      keyHash: await this.hashKey(key),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: Buffer.from(encryptedSymKey).toString('base64'),
    };

    return new Secret(
      Buffer.from(encryptedData).toString('base64'),
      metadata
    );
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

    // Decrypt the symmetric key
    const encryptedSymKey = Buffer.from(secretObj.getMetadata().symmetricKey, 'base64');
    const symmetricKeyBuffer = await crypto.subtle.decrypt(
      {
        name: this.ALGORITHM,
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
    const iv = Buffer.from(secretObj.getMetadata().iv, 'base64');

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

  private static async wrapKey(
    key: CryptoKey,
    passphrase: string
  ): Promise<WrappedKeyData> {
    // First export the private key to wrap it
    const keyData = await crypto.subtle.exportKey('pkcs8', key);
    
    // Generate a wrapping key from the passphrase
    const wrappingKey = await this.generateKeyFromPassphrase(passphrase);
    
    // Generate IV for encryption
    const iv = crypto.getRandomValues(new Uint8Array(12));
    
    // Wrap the exported key data
    const wrapped = await crypto.subtle.encrypt(
      { name: this.SYMMETRIC_ALGORITHM, iv },
      wrappingKey,
      keyData
    );
    
    // Return the wrapped key data in base64 format
    return {
      wrappedKey: Buffer.from(wrapped).toString('base64'),
      iv: Buffer.from(iv).toString('base64')
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
    
    // Import the unwrapped key
    return crypto.subtle.importKey(
      'pkcs8',
      unwrappedData,
      {
        name: this.ALGORITHM,
        hash: this.HASH,
      },
      true,
      ['decrypt']
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