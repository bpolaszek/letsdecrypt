import {describe, expect, it} from 'vitest'
import {decrypt, encrypt, exportKeyPair, generateKeyPair} from '../src'
import {payload as sensitiveData} from './data'

describe.each([{sensitiveData}, {sensitiveData, passphrase: 'May the 4th be with you.'}])(
  'AES keys with passphrase $passphrase',
  function ({sensitiveData, passphrase}) {
    let keyPair, serializedKeys, encryptedSecret, serializedSecret
    it('generates a key pair', async function () {
      keyPair = await generateKeyPair({
        algorithm: 'AES',
        passphrase,
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
  }
)
