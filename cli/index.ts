#!/usr/bin/env node

import minimist from 'minimist'
import match from 'match-operator'
import {generatePrivateKeyCommand} from './generate-private-key-command'
import {Argv} from './input'
import {generatePublicKeyCommand} from './generate-public-key-command'
import {encryptCommand} from './encrypt-command'
import {decryptCommand} from './decrypt-command'
;(async () => {
  const argv: Argv = minimist(process.argv.slice(2))
  const commandName = argv['_'][0] ?? undefined
  argv['_'].shift()
  const args = argv['_']
  const options = argv
  // @ts-ignore
  delete options['_']

  const commandToRun = () =>
    match(commandName, [
      ['private-key:generate', () => generatePrivateKeyCommand(args, options as any)],
      ['public-key:generate', () => generatePublicKeyCommand(args, options as any)],
      ['encrypt', () => encryptCommand(args, options as any)],
      ['decrypt', () => decryptCommand(args, options as any)],
    ])
  try {
    console.log(await commandToRun())
    process.exit(0)
  } catch (e) {
    console.error(e)
    process.exit(1)
  }
})()
