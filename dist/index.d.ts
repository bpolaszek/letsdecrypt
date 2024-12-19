import { CryptoKeyPair, KeyPairOptions, MaybeSerializedKey, Secret, SerializedKeyPair, WrappedCryptoKeyPair } from './common';
export declare const importPrivateKey: (privateKey: MaybeSerializedKey, passphrase?: string) => Promise<CryptoKey>;
export declare const generateKeyPair: (options?: KeyPairOptions) => Promise<WrappedCryptoKeyPair>;
export declare const exportKeyPair: (keyPair: CryptoKeyPair | WrappedCryptoKeyPair) => Promise<SerializedKeyPair>;
export declare const encrypt: (data: string, publicKey: MaybeSerializedKey) => Promise<Secret>;
export declare const decrypt: (secret: Secret | string, privateKey: MaybeSerializedKey, passphrase?: string) => Promise<string>;
