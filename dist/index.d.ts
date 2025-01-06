import { CryptoKeyPair, KeyPairOptions, MaybeSerializedKey, Secret, SerializedKeyPair, WrappedCryptoKeyPair, WrappedKeyData } from './common';
export declare const changePassphrase: (privateKey: MaybeSerializedKey, oldPassphrase: string | null, newPassphrase: string | null) => Promise<WrappedKeyData>;
export declare const generateKeyPair: (options?: KeyPairOptions) => Promise<WrappedCryptoKeyPair>;
export declare const exportKeyPair: (keyPair: CryptoKeyPair | WrappedCryptoKeyPair) => Promise<SerializedKeyPair>;
export declare const encrypt: (data: string, publicKey: MaybeSerializedKey) => Promise<Secret>;
export declare const decrypt: (secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string) => Promise<string>;
