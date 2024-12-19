import {createApp} from 'vue'
import App from './App.vue'
import {Aes} from "../src/aes"

createApp(App).mount('#app')

const log = async () => {
  let keyPair = await Aes.generateKeyPair()
  const {privateKey: wrappedPrivateKey} = keyPair
  console.log(wrappedPrivateKey)
  let privateKey = await Aes.importPrivateKey(wrappedPrivateKey)
  console.log(privateKey)
  const secret = await Aes.encrypt('Hello world', privateKey)
  console.log(secret)
  const decrypted = await Aes.decrypt(secret, privateKey)
  console.log(decrypted)
}
log()
