import {describe, expect, it} from 'vitest'
import {generateKeyPair, encrypt, exportKeyPair, decrypt} from '../src'
import {payload as sensitiveData} from './data'

describe.each([
  {sensitiveData},
])('AES keys with passphrase $passphrase', function ({sensitiveData}) {
  let keyPair, serializedKeys, encryptedSecret, serializedSecret, passphrase
  it('generates a key pair', async function () {
    keyPair = await generateKeyPair({
      algorithm: 'AES',
    })
    const {publicKey, privateKey} = keyPair
    expect(publicKey).toBeDefined()
    expect(privateKey).toBeDefined()
  })

  it('serializes the keys', async function () {
    serializedKeys = await exportKeyPair(keyPair)
    const {publicKey, privateKey} = serializedKeys
    expect(publicKey).toBeTypeOf('string')
    expect(privateKey).toBeTypeOf('string')
  })

  it('encrypts a secret', async function () {
    encryptedSecret = await encrypt(sensitiveData, serializedKeys.publicKey)
    expect(encryptedSecret.encryptedData).toBeTypeOf('string')
    serializedSecret = JSON.stringify(encryptedSecret)
  })

  it('decrypts a secret', async function () {
    let decrypted = await decrypt(serializedSecret, serializedKeys.privateKey, passphrase)
    expect(decrypted).toBe(sensitiveData)
  })
})
