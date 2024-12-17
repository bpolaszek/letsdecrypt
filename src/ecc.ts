import {
  type AlgorithmId,
  AbstractCryptoService,
  Secret,
  type SecretMetadata,
  type WrappedKeyData,
  type KeyPairOptions,
} from "./common"
import { Buffer } from "buffer"

export class Ecc extends AbstractCryptoService {
  private static readonly DEFAULT_ECC_CURVE = 'P-256';

  static override getPublicKeyUsages(): KeyUsage[] {
    return []
  }

  static override getPrivateKeyUsages(): KeyUsage[] {
    return ['deriveKey', 'deriveBits'];
  }

  static override getKeyPairUsages(): KeyUsage[] {
    return ['deriveKey', 'deriveBits'];
  }

  static override getAlgorithm(): AlgorithmId {
    return 'ECDH'
  }

  protected static override getKeyGenParams(options?: KeyPairOptions): RsaHashedKeyGenParams | EcKeyGenParams {
    return {
      name: this.ECC_ALGORITHM,
      namedCurve: options?.eccCurve || this.DEFAULT_ECC_CURVE,
    };
  }

  protected static override async unwrapKey(
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
    const importParams = { name: this.ECC_ALGORITHM, namedCurve: this.DEFAULT_ECC_CURVE }

    return crypto.subtle.importKey(
      format,
      keyData,
      importParams,
      true,
      this.getPrivateKeyUsages()
    );
  }

  static async encrypt(
    data: string,
    publicKey: CryptoKey,
  ): Promise<Secret> {
    // For ECC, we need to:
    // 1. Generate an ephemeral key pair
    // 2. Derive a shared secret using ECDH
    // 3. Use the shared secret to encrypt the data
    const keyAlgorithm = publicKey.algorithm as EcKeyImportParams | RsaHashedImportParams;
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
        public: publicKey,
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
      keyHash: await this.hashKey(publicKey),
      iv: Buffer.from(iv).toString('base64'),
      symmetricKey: '', // Not needed for ECC
      publicKey: Buffer.from(exportedEphemeralKey).toString('base64')
    };

    return new Secret(
      Buffer.from(encryptedData).toString('base64'),
      metadata
    );
  }

  static async decrypt(
    secret: Secret | string,
    privateKey: CryptoKey | string | WrappedKeyData,
    passphrase?: string,
  ): Promise<string> {
    // Import the ephemeral public key
    const secretObj = typeof secret === 'string' ? Secret.deserialize(secret) : secret
    let key: CryptoKey

    if (typeof privateKey === 'string') {
      key = await this.importPrivateKey(privateKey, passphrase)
    } else if ('wrappedKey' in privateKey) {
      key = await this.unwrapKey(privateKey, passphrase ?? '')
    } else {
      key = privateKey
    }

    const ephemeralPublicKey = await crypto.subtle.importKey(
      'spki',
      Buffer.from(secretObj.getMetadata().publicKey!, 'base64'),
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
    const iv = Buffer.from(secretObj.getMetadata().iv!, 'base64');

    const decryptedData = await crypto.subtle.decrypt(
      {
        name: this.SYMMETRIC_ALGORITHM,
        iv,
      },
      sharedSecret,
      encryptedData
    );

    return new TextDecoder().decode(decryptedData);
  }
}
