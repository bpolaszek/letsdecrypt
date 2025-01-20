import {Arguments, Options} from './input'
import {required} from './required'
import {encrypt, serializeSecret} from '../src'

type EncryptCommandOptions = Options & {
  'public-key': string
}

export async function encryptCommand([value]: Arguments, options: EncryptCommandOptions) {
  const publicKey = options['public-key'] ?? required()
  return serializeSecret(await encrypt(value, publicKey))
}
