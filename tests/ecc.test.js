import {describe, expect, it} from 'vitest'
import {generateKeyPair, encrypt, exportKeyPair, decrypt, changePassphrase} from '../src'
import {payload as sensitiveData} from './data'

describe.each([
  {sensitiveData},
  {sensitiveData, passphrase: 'May the 4th be with you'},
  {sensitiveData, eccCurve: 'P-384'},
  {sensitiveData, eccCurve: 'P-384', passphrase: 'May the 4th be with you'},
  {sensitiveData, eccCurve: 'P-521'},
  {sensitiveData, eccCurve: 'P-521', passphrase: 'May the 4th be with you'},
])('ECC keys with passphrase $passphrase', function ({sensitiveData, eccCurve, passphrase}) {
  let keyPair, serializedKeys, encryptedSecret, serializedSecret
  it('generates a key pair', async function () {
    keyPair = await generateKeyPair({
      algorithm: 'ECC',
      eccCurve,
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

  it('cannot decrypt a secret with the wrong private key', async function () {
    keyPair = await generateKeyPair({
      algorithm: 'ECC',
      eccCurve,
      passphrase,
    })
    const serializedKeys = await exportKeyPair(keyPair)
    const {privateKey} = serializedKeys
    try {
      await decrypt(serializedSecret, privateKey, passphrase)
      expect(true).toBe(false) // This line should not be reached
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('cannot decrypt a secret with the wrong passphrase', async function () {
    try {
      await decrypt(serializedSecret, serializedKeys.privateKey, 'wrong passphrase')
      expect(true).toBe(false) // This line should not be reached
    } catch (e) {
      expect(e).toBeInstanceOf(Error)
    }
  })

  it('changes the passphrase', async function () {
    const newPrivateKey = await changePassphrase(serializedKeys.privateKey, passphrase, 'C0vf3f3')
    let decrypted = await decrypt(serializedSecret, newPrivateKey, 'C0vf3f3')
    expect(decrypted).toBe(sensitiveData)
  })
})
