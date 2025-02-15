import {Arguments, Options} from './input'
import {required} from './required'
import {derivePublicKey, serializeKey} from '../src'

type GeneratePublicKeyCommandOptions = Options & {
  'private-key': string
  passphrase?: string
}

export async function generatePublicKeyCommand(args: Arguments, options: GeneratePublicKeyCommandOptions) {
  const privateKey = options['private-key'] ?? required()
  return serializeKey(await derivePublicKey(privateKey, options.passphrase ?? ''))
}
