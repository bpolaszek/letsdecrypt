import {describe, expect, it} from 'vitest'
import {CryptoService} from '../src'
import {payload as sensitiveData} from './data'

describe.each([
  {sensitiveData},
  {sensitiveData, passphrase: 'May the 4th be with you'},
  {sensitiveData, modulusLength: 3072},
  {sensitiveData, modulusLength: 3072, passphrase: 'May the 4th be with you'},
  {sensitiveData, modulusLength: 4096},
  {sensitiveData, modulusLength: 4096, passphrase: 'May the 4th be with you'},
])('RSA keys with passphrase $passphrase', function ({sensitiveData, modulusLength, passphrase}) {
  let keyPair, serializedKeys, encryptedSecret
  it('generates a key pair', async function () {
    keyPair = await CryptoService.generateKeyPair({
      algorithm: 'RSA',
      modulusLength,
      passphrase,
    })
    const {publicKey, privateKey} = keyPair
    expect(publicKey).toBeDefined()
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
    const metadata = encryptedSecret.metadata
    expect(metadata.algorithm).toBe('RSA-OAEP')
  })

  it('decrypts a secret', async function () {
    let decrypted = await CryptoService.decrypt(encryptedSecret, keyPair.privateKey, passphrase)
    expect(decrypted).toBe(sensitiveData)
  })
})
