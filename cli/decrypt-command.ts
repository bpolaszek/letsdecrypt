import {Arguments, Options} from './input'
import {required} from './required'
import {decrypt} from '../src'

type DecryptCommandOptions = Options & {
  'private-key': string
  passphrase?: string
}

export async function decryptCommand([value]: Arguments, options: DecryptCommandOptions) {
  const privateKey = options['private-key'] ?? required()
  return await decrypt(value, privateKey, options.passphrase ?? '')
}
