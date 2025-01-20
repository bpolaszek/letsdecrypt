import {Arguments, Options} from './input'
import {required} from './required'
import {encrypt, serializeSecret} from '../src'

type EncryptCommandOptions = Options & {
  'public-key': string
  'is-base64'?: boolean
  'to-base64'?: boolean
}

export async function encryptCommand([value]: Arguments, options: EncryptCommandOptions) {
  try {
    const publicKey = options['public-key'] ?? required()

    return serializeSecret(await encrypt(value, publicKey))
  } catch (err) {
    console.error('Error reading stdin:', err)
    throw err
  }
}
