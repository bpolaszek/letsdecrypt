import {exportKeyPair, generateKeyPair, KeyPairOptions} from '../src'
import {Arguments} from './input'

// @ts-ignore
export const generatePrivateKeyCommand = async (args: Arguments, options: KeyPairOptions) => {
  const {privateKey} = await exportKeyPair(await generateKeyPair(options))
  return privateKey
}
