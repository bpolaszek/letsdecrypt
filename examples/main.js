import {encrypt, generateKeyPair} from '../src/index'
import {createApp} from 'vue'
import {wrapPublicKey} from '../src/common'
import App from './App.vue'
import {Aes} from '../src/aes'

createApp(App).mount('#app')

const log1 = async () => {
  let keyPair = await Aes.generateKeyPair()
  const {privateKey: wrappedPrivateKey} = keyPair
  console.log(wrappedPrivateKey)
  let privateKey = await Aes.importPrivateKey(wrappedPrivateKey, '')
  console.log(privateKey)
  const secret = await Aes.encrypt('Hello world', wrappedPrivateKey)
  console.log(secret)
  const decrypted = await Aes.decrypt(secret, wrappedPrivateKey)
  console.log(decrypted)
}
//log1()
const log2 = async () => {
  let keyPair = await Aes.generateKeyPair({passphrase: 'May the 4th be with you.'})
  const {privateKey: wrappedPrivateKey} = keyPair
  console.log(wrappedPrivateKey)
  let privateKey = await Aes.importPrivateKey(wrappedPrivateKey, 'May the 4th be with you.')
  console.log(privateKey)
  const secret = await Aes.encrypt('Hello world', privateKey)
  console.log(secret)
  const decrypted = await Aes.decrypt(secret, wrappedPrivateKey, 'May the 4th be with you.')
  console.log(decrypted)
}
//log2()

const log3 = async () => {
  const keyPair = await generateKeyPair({passphrase: 'May the 4th be with you.', algorithm: 'AES'})
  const {privateKey: wrappedPrivateKey} = keyPair
  console.log(wrappedPrivateKey)
  const secret = await encrypt('Hello world', keyPair.publicKey)
  console.log(secret)
}
log3()
