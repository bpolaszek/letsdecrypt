import { CryptoService, Secret, type SecretMetadata, type WrappedKeyData } from "./common"
import { Buffer } from "buffer"

export class Rsa extends CryptoService {

  protected static override getPublicKeyUsages(algorithm: string): KeyUsage[] {
    return ['encrypt']
  }

  protected static override getPrivateKeyUsages(algorithm: string): KeyUsage[] {
    return ['decrypt']
  }

  protected static override getKeyPairUsages(algorithm: string): KeyUsage[] {
    return ['encrypt', 'decrypt']
  }

  static async importPublicKey(serialized: string): Promise<CryptoKey> {
    const binaryKey = Buffer.from(serialized, 'base64')
    return await crypto.subtle.importKey(
      'spki',
      binaryKey,
      {
        name: this.RSA_ALGORITHM,
        hash: this.HASH,
      },
      true,
      this.getPublicKeyUsages(this.RSA_ALGORITHM),
    )
  }

  static async importPrivateKey(
    serialized: string,
    passphrase?: string,
  ): Promise<CryptoKey> {
    const wrappedKeyData: WrappedKeyData = JSON.parse(serialized)
    return this.unwrapKey(wrappedKeyData, passphrase ?? '')
  }

  static async encrypt(
    data: string,
    publicKey: CryptoKey | string,
  ): Promise<Secret> {
    const key = typeof publicKey === 'string'
      ? await this.importPublicKey(publicKey)
      : publicKey

    // RSA encryption path (unchanged)
    // Generate a symmetric key for the actual data encryption
    const symmetricKey = await crypto.subtle.generateKey(
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256,
      },
      true,
      ['encrypt', 'decrypt'],
    )

    // Generate IV
    const iv = crypto.getRandomValues(new Uint8Array(12))

    // Encrypt the data with the symmetric key
    const encodedData = new TextEncoder().encode(data)
    const encryptedData = await crypto.subtle.encrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv,
      },
      symmetricKey,
      encodedData,
    )

    // Export and encrypt the symmetric key with the public key
    const exportedSymKey = await crypto.subtle.exportKey('raw', symmetricKey)
    const encryptedSymKey = await crypto.subtle.encrypt(
      {
        name: this.RSA_ALGORITHM,
      },
      key,
      exportedSymKey,
    )

    // Create metadata
    const metadata: SecretMetadata = {
      algorithm: this.RSA_ALGORITHM,
      keyHash: await this.hashKey(key),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: Buffer.from(encryptedSymKey).toString('base64'),
    }

    return new Secret(
      Buffer.from(encryptedData).toString('base64'),
      metadata,
    )
  }

  static async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string,
  ): Promise<string> {
    const secretObj = typeof secret === 'string' ? Secret.deserialize(secret) : secret
    let key: CryptoKey

    if (typeof privateKey === 'string') {
      key = await this.importPrivateKey(privateKey, passphrase)
    } else if ('wrappedKey' in privateKey) {
      key = await this.unwrapKey(privateKey, passphrase ?? '')
    } else {
      key = privateKey
    }

    const metadata = secretObj.getMetadata()
    // Decrypt the symmetric key
    const encryptedSymKey = Buffer.from(metadata.symmetricKey, 'base64')
    const symmetricKeyBuffer = await crypto.subtle.decrypt(
      {
        name: this.RSA_ALGORITHM,
      },
      key,
      encryptedSymKey,
    )

    // Import the symmetric key
    const symmetricKey = await crypto.subtle.importKey(
      'raw',
      symmetricKeyBuffer,
      {
        name: this.SYMMETRIC_ALGORITHM,
        length: 256,
      },
      false,
      ['decrypt'],
    )

    // Decrypt the data
    const encryptedData = Buffer.from(secretObj.getEncryptedData(), 'base64')
    const iv = Buffer.from(metadata.iv, 'base64')

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv,
      },
      symmetricKey,
      encryptedData,
    )

    return new TextDecoder().decode(decryptedData)
  }

  private static async unwrapKey(
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
        hash: this.HASH
      },
      true,
      this.getPrivateKeyUsages(wrappedData.algorithm),
    )
  }
}
