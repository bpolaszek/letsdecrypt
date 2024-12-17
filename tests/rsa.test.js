// @vitest-environment happy-dom
import {describe, it, expect} from "vitest"
import {CryptoService, Secret} from "../utils/crypto"
import {payload} from './data'

describe.each([
  {passphrase: '', modulusLength: 2048, sensitiveData: payload},
  {passphrase: 'May the 4th be with you', modulusLength: 2048, sensitiveData: payload},
  {passphrase: '', modulusLength: 3072, sensitiveData: payload},
  {passphrase: 'May the 4th be with you', modulusLength: 3072, sensitiveData: payload},
  {passphrase: '', modulusLength: 4096, sensitiveData: payload},
  {passphrase: 'May the 4th be with you', modulusLength: 4096, sensitiveData: payload},
])('RSA keys with passphrase $passphrase', function ({passphrase, modulusLength, sensitiveData}) {

  let keyPair, serializedKeys, encryptedSecret
  it('generates a key pair', async function () {
    keyPair = await CryptoService.generateKeyPair({
      algorithm: 'RSA',
      modulusLength,
      passphrase,
    })
    const {publicKey, privateKey} = keyPair
    expect(publicKey).toBeInstanceOf(CryptoKey)
    expect(privateKey).toBeDefined()
  })

  it('serializes the keys', async function () {
    serializedKeys = await CryptoService.exportKeyPair(keyPair)
    const {publicKey, privateKey} = serializedKeys
    expect(publicKey).toBeTypeOf('string')
    expect(privateKey).toBeTypeOf('string')
  })

  it('encrypts a secret', async function () {
    encryptedSecret = await CryptoService.encrypt(sensitiveData, serializedKeys.publicKey)
    expect(encryptedSecret).toBeInstanceOf(Secret)
  })

  it('decrypts a secret', async function () {
    let decrypted = await CryptoService.decrypt(encryptedSecret, keyPair.privateKey, passphrase)
    expect(decrypted).toBe(sensitiveData)
  })

})
