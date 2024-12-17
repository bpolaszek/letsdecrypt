import { type AlgorithmId, AbstractCryptoService, Secret, type SecretMetadata, type WrappedKeyData } from "./common"
import { Buffer } from "buffer"

export class Rsa extends AbstractCryptoService {

  static override getPublicKeyUsages(): KeyUsage[] {
    return ['encrypt']
  }

  static override getPrivateKeyUsages(): KeyUsage[] {
    return ['decrypt']
  }

  static override getKeyPairUsages(): KeyUsage[] {
    return ['encrypt', 'decrypt']
  }

  static override getAlgorithm(): AlgorithmId {
    return 'RSA-OAEP'
  }

  static async encrypt(
    data: string,
    publicKey: CryptoKey,
  ): Promise<Secret> {
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
      publicKey,
      exportedSymKey,
    )

    // Create metadata
    const metadata: SecretMetadata = {
      algorithm: this.RSA_ALGORITHM,
      keyHash: await this.hashKey(publicKey),
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
}
