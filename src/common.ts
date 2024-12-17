import { Buffer } from "buffer"

export type Algorithm = 'RSA' | 'ECC'
export type AlgorithmId = 'RSA-OAEP' | 'ECDH'

export interface KeyPairOptions {
  passphrase?: string;
  algorithm?: Algorithm;
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
  publicKey: WrappedKeyData;
  privateKey: WrappedKeyData;
}

export class Secret {
  private readonly encryptedData: string;
  private readonly metadata: SecretMetadata;

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

export abstract class AbstractCryptoService {

  protected static readonly RSA_ALGORITHM = 'RSA-OAEP'
  protected static readonly ECC_ALGORITHM = 'ECDH'
  protected static readonly SYMMETRIC_ALGORITHM = 'AES-GCM'
  protected static readonly DEFAULT_RSA_LENGTH = 2048
  protected static readonly HASH = 'SHA-256'

  static getPublicKeyUsages(): KeyUsage[] {
    throw Error('Abstract static method getPublicKeyUsages has not been implemented.')
  }

  static getPrivateKeyUsages(): KeyUsage[] {
    throw Error('Abstract static method getPrivateKeyUsages has not been implemented.')
  }

  static getKeyPairUsages(): KeyUsage[] {
    throw Error('Abstract static method getKeyPairUsages has not been implemented.')
  }

  static getAlgorithm(): AlgorithmId {
    throw Error('Abstract static method getAlgorithm has not been implemented.')
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

  protected static async wrapPublicKey(key: CryptoKey, algorithm: string): Promise<WrappedKeyData> {
    return {
      wrappedKey: Buffer.from(await crypto.subtle.exportKey('spki', key)).toString('base64'),
      iv: Buffer.from(crypto.getRandomValues(new Uint8Array(12))).toString('base64'),
      format: 'spki',
      algorithm,
    }
  }

  protected static async wrapPrivateKey(
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

    return {
      wrappedKey: Buffer.from(wrapped).toString('base64'),
      iv: Buffer.from(iv).toString('base64'),
      algorithm,
      format,
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
      this.getKeyPairUsages(),
    )
    // If passphrase provided, wrap the private key
    const wrappedPrivateKey = await this.wrapPrivateKey(keyPair.privateKey, options?.passphrase ?? '', params.name)
    const wrappedPublicKey = await this.wrapPublicKey(keyPair.publicKey, params.name)
    return {
      publicKey: wrappedPublicKey,
      privateKey: wrappedPrivateKey,
    }
  }

  protected static async hashKey(key: CryptoKey): Promise<string> {
    const exported = await crypto.subtle.exportKey('spki', key)
    const hashBuffer = await crypto.subtle.digest(this.HASH, exported)
    return Buffer.from(hashBuffer).toString('hex')
  }

  protected static async unwrapKey(
    wrappedData: WrappedKeyData,
    passphrase: string,
  ): Promise<CryptoKey> {
    // Generate the unwrapping key from the passphrase
    const unwrappingKey = await this.generateKeyFromPassphrase(passphrase)

    // Decode the wrapped key and IV from base64
    const wrappedKey = Buffer.from(wrappedData.wrappedKey, 'base64')
    const iv = Buffer.from(wrappedData.iv, 'base64')

    // Decrypt the wrapped key
    const unwrappedData = await crypto.subtle.decrypt(
      {name: this.SYMMETRIC_ALGORITHM, iv},
      unwrappingKey,
      wrappedKey,
    )

    // Handle the unwrapped data based on the original format
    const format = (wrappedData as any).format || 'pkcs8'
    const keyData = format === 'jwk' ?
      JSON.parse(new TextDecoder().decode(unwrappedData)) :
      unwrappedData

    return crypto.subtle.importKey(
      format,
      keyData,
      {
        name: this.RSA_ALGORITHM,
        hash: this.HASH,
      },
      true,
      this.getPrivateKeyUsages(),
    )
  }

  static async importPrivateKey(
    serialized: string,
    passphrase?: string,
  ): Promise<CryptoKey> {
    const wrappedKeyData: WrappedKeyData = JSON.parse(serialized)
    return this.unwrapKey(wrappedKeyData, passphrase ?? '')
  }
}
