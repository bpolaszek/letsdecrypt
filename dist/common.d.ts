export type Algorithm = 'RSA' | 'ECC' | 'AES';
export interface KeyPairOptions {
    passphrase?: string;
    algorithm?: Algorithm;
    rsaModulusLength?: number;
    eccCurve?: 'P-256' | 'P-384' | 'P-521';
}
export interface SerializedKeyPair {
    publicKey: string;
    privateKey: string;
    fingerprint: string;
}
export interface SecretMetadata {
    algorithm: string;
    keyHash: string;
    symmetricKey?: string;
    iv?: string;
    publicKey?: string;
    namedCurve?: string;
}
export interface WrappedKeyData {
    fingerprint: string;
    wrappedKey: string;
    algorithm: string;
    format: string;
    iv?: string;
    namedCurve?: string;
    protected?: boolean;
}
export interface CryptoKeyPair {
    publicKey: CryptoKey;
    privateKey: CryptoKey;
}
export interface WrappedCryptoKeyPair {
    publicKey: WrappedKeyData;
    privateKey: WrappedKeyData;
    fingerprint: string;
}
export type Secret = {
    encryptedData: string;
    metadata: SecretMetadata;
};
export interface CryptoServiceAlgorithmInterface {
    generateKeyPair(options?: KeyPairOptions): Promise<WrappedCryptoKeyPair>;
    encrypt(data: string, publicKey: MaybeSerializedKey): Promise<Secret>;
    decrypt(secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string): Promise<string>;
    importPrivateKey(wrappedData: MaybeSerializedKey, passphrase: string): Promise<CryptoKey>;
    importPublicKey(wrappedData: MaybeSerializedKey): Promise<CryptoKey>;
}
export type MaybeSerializedKey = string | WrappedKeyData | CryptoKey;
export declare const generateKeyFromPassphrase: (passphrase: string) => Promise<CryptoKey>;
export declare const wrapPublicKey: (key: CryptoKey, algorithm: string, fingerprint: string, namedCurve?: string) => Promise<WrappedKeyData>;
export declare const wrapPrivateKey: (key: CryptoKey, passphrase: string, algorithm: string, fingerprint: string, namedCurve?: string) => Promise<WrappedKeyData>;
export declare const hashKey: (key: CryptoKey, format?: string) => Promise<string>;
