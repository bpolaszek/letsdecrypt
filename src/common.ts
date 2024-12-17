import { Buffer } from "buffer"

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

export abstract class CryptoService {

  protected static readonly RSA_ALGORITHM = 'RSA-OAEP'
  protected static readonly ECC_ALGORITHM = 'ECDH'
  protected static readonly SYMMETRIC_ALGORITHM = 'AES-GCM'
  protected static readonly WRAP_ALGORITHM = 'AES-KW'
  protected static readonly DEFAULT_RSA_LENGTH = 2048
  protected static readonly DEFAULT_ECC_CURVE = 'P-256'
  protected static readonly HASH = 'SHA-256'

  protected static getPublicKeyUsages(algorithm: string): KeyUsage[] {
    throw Error('Abstract static method getPublicKeyUsages was not implemented.')
  }
  protected static getPrivateKeyUsages(algorithm: string): KeyUsage[] {
    throw Error('Abstract static method getPrivateKeyUsages was not implemented.')
  }
  protected static getKeyPairUsages(algorithm: string): KeyUsage[] {
    throw Error('Abstract static method getKeyPairUsages was not implemented.')
  }

  protected static async generateKeyFromPassphrase(
    passphrase: string,
  ): Promise<CryptoKey> {
    const encoder = new TextEncoder()
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      encoder.encode(passphrase),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey'],
    )

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
      ['encrypt', 'decrypt'],
    )
  }

  protected static async wrapKey(
    key: CryptoKey,
    passphrase: string,
    algorithm: string,
  ): Promise<WrappedKeyData> {
    // First export the private key to wrap it
    const format = algorithm === this.ECC_ALGORITHM ? 'jwk' : 'pkcs8'
    const keyData = await crypto.subtle.exportKey(format, key)
    const keyBytes = format === 'jwk' ?
      new TextEncoder().encode(JSON.stringify(keyData)) :
      new Uint8Array(keyData as ArrayBuffer)

    // Generate a wrapping key from the passphrase
    const wrappingKey = await this.generateKeyFromPassphrase(passphrase)

    // Generate IV for encryption
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Wrap the exported key data
    const wrapped = await crypto.subtle.encrypt(
      {name: this.SYMMETRIC_ALGORITHM, iv},
      wrappingKey,
      keyBytes,
    )

    // Return the wrapped key data in base64 format with format information
    return {
      wrappedKey: Buffer.from(wrapped).toString('base64'),
      iv: Buffer.from(iv).toString('base64'),
      algorithm,
      format, // Add format information
    }
  }

  protected static getKeyGenParams(options?: KeyPairOptions): RsaHashedKeyGenParams | EcKeyGenParams {
    return {
      name: this.RSA_ALGORITHM,
      modulusLength: options?.rsaModulusLength || this.DEFAULT_RSA_LENGTH,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: this.HASH,
    }
  }

  static async generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair> {
    const params = this.getKeyGenParams(options)
    const keyPair = await crypto.subtle.generateKey(
      params,
      true,
      this.getKeyPairUsages(params.name),
    )
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey = await this.wrapKey(keyPair.privateKey, options?.passphrase ?? '', params.name)
    return {
      publicKey: keyPair.publicKey,
      privateKey: wrappedPrivateKey,
    }
  }

  static async exportKeyPair(keyPair: CryptoKeyPair | WrappedCryptoKeyPair): Promise<SerializedKeyPair> {
    const exportedPublic = await crypto.subtle.exportKey('spki', keyPair.publicKey)
    return {
      publicKey: Buffer.from(exportedPublic).toString('base64'),
      privateKey: JSON.stringify(keyPair.privateKey),
    }
  }

  protected static async hashKey(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key)
    const hashBuffer = await crypto.subtle.digest(this.HASH, exported)
    return Buffer.from(hashBuffer).toString('hex')
  }
}
