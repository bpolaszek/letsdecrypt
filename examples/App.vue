<template>
  <div class="container mx-auto p-4">
    <h1 class="text-2xl font-bold mb-6">Let's Decrypt</h1>

    <!-- Key Generation -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Generate Key Pair</h2>
      <div class="space-y-4">
        <div>
          <label class="block mb-2">Algorithm</label>
          <select v-model="algorithm" class="border p-2 rounded w-full">
            <option value="RSA">RSA</option>
            <option value="ECC">ECC (Elliptic Curve)</option>
            <option value="AES">AES (Symmetric encryption)</option>
          </select>
        </div>

        <!-- RSA Options -->
        <div v-if="algorithm === 'RSA'">
          <label class="block mb-2">RSA Key Length</label>
          <select v-model="rsaModulusLength" class="border p-2 rounded w-full">
            <option :value="2048">2048 bits (Standard)</option>
            <option :value="3072">3072 bits (Extra Strong)</option>
            <option :value="4096">4096 bits (Maximum Security)</option>
          </select>
        </div>

        <!-- ECC Options -->
        <div v-if="algorithm === 'ECC'">
          <label class="block mb-2">ECC Curve</label>
          <select v-model="eccCurve" class="border p-2 rounded w-full">
            <option value="P-256">P-256 (Standard)</option>
            <option value="P-384">P-384 (Extra Strong)</option>
            <option value="P-521">P-521 (Maximum Security)</option>
          </select>
        </div>

        <div>
          <label class="block mb-2">Passphrase (optional)</label>
          <input v-model="passphrase" type="text" class="border p-2 rounded w-full" placeholder="Enter passphrase" />
        </div>

        <section v-html="keyGenerationCodeBlock" class="*:rounded-lg *:py-2 *:px-4 *:leading-tight text-sm" />

        <button @click="generateKeyPair" class="bg-blue-500 text-white px-4 py-2 rounded">Generate Keys</button>
      </div>

      <div v-if="keyPair" class="mt-4 space-y-4">
        <div>
          <label class="block mb-2">Key Fingerprint</label>
          <code class="block p-2 bg-gray-100 rounded font-mono">{{ keyPair.fingerprint }}</code>
        </div>
        <div>
          <label class="block mb-2">Public Key</label>
          <textarea v-model="serializedKeys.publicKey" readonly class="border p-2 rounded w-full h-32"></textarea>
        </div>
        <div>
          <label class="block mb-2">Private Key</label>
          <textarea v-model="serializedKeys.privateKey" readonly class="border p-2 rounded w-full h-32"></textarea>
        </div>
      </div>
    </section>

    <!-- Encryption -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Encrypt Message</h2>
      <div class="space-y-4">
        <div>
          <div class="flex mb-2 items-center gap-3">
            <label>Public Key</label>
            <button
              v-if="serializedKeys.publicKey"
              type="button"
              class="text-xs opacity-60 text-light"
              @click="encryptionPublicKey = serializedKeys.publicKey">
              Paste from above
            </button>
          </div>
          <textarea
            v-model="encryptionPublicKey"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste public key here"></textarea>
        </div>
        <div>
          <label class="block mb-2">Message to Encrypt</label>
          <textarea
            v-model="messageToEncrypt"
            class="border p-2 rounded w-full h-32"
            placeholder="Enter message to encrypt"></textarea>
        </div>

        <section v-html="encryptionCodeBlock" class="*:rounded-lg *:py-2 *:px-4 *:leading-tight text-sm" />

        <button @click="encryptMessage" class="bg-green-500 text-white px-4 py-2 rounded">Encrypt</button>
      </div>

      <div v-if="encryptedSecret" class="mt-4">
        <label class="block mb-2">Encrypted Secret</label>
        <textarea v-model="serializedSecret" readonly class="border p-2 rounded w-full h-32"></textarea>
      </div>
    </section>

    <!-- Decryption -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Decrypt Message</h2>
      <div class="space-y-4">
        <div>
          <div class="flex mb-2 items-center gap-3">
            <label>Private Key</label>
            <button
              v-if="serializedKeys.privateKey"
              type="button"
              class="text-xs opacity-60 text-light"
              @click="decryptionPrivateKey = serializedKeys.privateKey">
              Paste from above
            </button>
          </div>
          <textarea
            v-model="decryptionPrivateKey"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste private key here"></textarea>
        </div>
        <div>
          <div class="flex mb-2 items-center gap-3">
            <label>Passphrase (if required)</label>
            <button
              v-if="passphrase"
              type="button"
              class="text-xs opacity-60 text-light"
              @click="decryptionPassphrase = passphrase">
              Paste from above
            </button>
          </div>
          <input
            v-model="decryptionPassphrase"
            type="text"
            class="border p-2 rounded w-full"
            placeholder="Enter passphrase" />
        </div>
        <div>
          <div class="flex mb-2 items-center gap-3">
            <label>Encrypted Secret</label>
            <button
              v-if="serializedSecret"
              type="button"
              class="text-xs opacity-60 text-light"
              @click="secretToDecrypt = serializedSecret">
              Paste from above
            </button>
          </div>
          <textarea
            v-model="secretToDecrypt"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste encrypted secret here"></textarea>
        </div>

        <section v-html="decryptionCodeBlock" class="*:rounded-lg *:py-2 *:px-4 *:leading-tight text-sm" />

        <button @click="decryptMessage" class="bg-purple-500 text-white px-4 py-2 rounded">Decrypt</button>
      </div>

      <div v-if="decryptedMessage" class="mt-4">
        <label class="block mb-2">Decrypted Message</label>
        <textarea v-model="decryptedMessage" class="border p-2 rounded w-full h-32"></textarea>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import {reactive, ref} from 'vue'
import {Secret, SerializedKeyPair} from '../src/common'
import {decrypt, encrypt, exportKeyPair, generateKeyPair as doGenerateKeyPair} from '../src'
import {codeToHtml} from 'shiki/bundle/web'
import {asyncComputed} from '@vueuse/core'
import match from 'match-operator'

const code = 'const a = 1' // input code
const SHIKI_PARAMS = {lang: 'javascript', theme: 'vitesse-dark'}

// Key Generation
const algorithm = ref<'RSA' | 'ECC' | 'AES'>('RSA')
const rsaModulusLength = ref<number>(2048)
const eccCurve = ref<'P-256' | 'P-384' | 'P-521'>('P-256')
const passphrase = ref('')
const keyPair = ref<CryptoKeyPair | null>(null)
const serializedKeys = ref<SerializedKeyPair>({publicKey: '', privateKey: '', fingerprint: ''})
const keyGenerationCodeBlock = asyncComputed(() => {
  const params: any = match(algorithm.value, {
    RSA: reactive({algorithm: 'RSA', rsaModulusLength}),
    ECC: reactive({algorithm: 'ECC', eccCurve}),
    AES: {algorithm: 'AES'},
  })
  if (passphrase.value.length > 0) {
    params.passphrase = passphrase.value
  }

  const keyGenParamsAsString = JSON.stringify(params, null, 2).replace(/"([^"]+)":/g, '$1:')
  return codeToHtml(
    `
import {generateKeyPair, exportKeyPair} from 'letsdecrypt'

// Generate key pair
const keyPair = await generateKeyPair(${keyGenParamsAsString})

// Export keys
const {publicKey, privateKey} = await exportKeyPair(keyPair)
  `.trim(),
    SHIKI_PARAMS
  )
})

// Encryption
const encryptionPublicKey = ref('')
const messageToEncrypt =
  ref(`Lorem ipsum dolor sit amet, consectetur adipiscing elit. Maecenas metus purus, ultricies eget urna eu, ultricies suscipit sapien. Aliquam molestie suscipit dolor, et egestas ex bibendum ac.
Donec ac laoreet massa, ac lobortis ex. Fusce ac urna dolor. Etiam in consequat nibh. Vivamus ante tortor, congue ac diam in, viverra sollicitudin tortor.
Fusce ipsum diam, molestie a cursus id, vehicula posuere ipsum. Proin in eros est. Vivamus tincidunt, leo eget placerat ultrices, ante erat pharetra lacus, eget sodales mi libero sed risus.`)

const encryptionCodeBlock = asyncComputed(() => {
  return codeToHtml(
    `
import {encrypt} from 'letsdecrypt'

// Encrypt message
const encryptedSecret = await encrypt(payload, publicKey)
  `.trim(),
    SHIKI_PARAMS
  )
})

const encryptedSecret = ref<Secret | null>(null)
const serializedSecret = ref('')

// Decryption
const decryptionPrivateKey = ref('')
const decryptionPassphrase = ref('')
const secretToDecrypt = ref('')
const decryptedMessage = ref('')

const decryptionCodeBlock = asyncComputed(() => {
  if (decryptionPassphrase.value.length > 0) {
    return codeToHtml(
      `
import {decrypt} from 'letsdecrypt'

// Decrypt message
const decryptedSecret = await decrypt(encryptedSecret, privateKey, "${decryptionPassphrase.value}")
  `.trim(),
      SHIKI_PARAMS
    )
  } else {
    return codeToHtml(
      `
import {decrypt} from 'letsdecrypt'

// Decrypt message
const decryptedSecret = await decrypt(encryptedSecret, privateKey)
  `.trim(),
      SHIKI_PARAMS
    )
  }
})

async function generateKeyPair() {
  try {
    const options = {
      algorithm: algorithm.value,
      passphrase: passphrase.value || undefined,
      ...(algorithm.value === 'RSA' ? {rsaModulusLength: rsaModulusLength.value} : {}),
      ...(algorithm.value === 'ECC' ? {eccCurve: eccCurve.value} : {}),
    }

    keyPair.value = await doGenerateKeyPair(options)
    serializedKeys.value = await exportKeyPair(keyPair.value)
  } catch (e) {
    console.error('Error generating key pair:', (e as Error).message)
    alert('Failed to generate key pair: ' + (e as Error).message)
  }
}

async function encryptMessage() {
  try {
    if (!encryptionPublicKey.value || !messageToEncrypt.value) {
      alert('Please provide both public key and message')
      return
    }

    encryptedSecret.value = await encrypt(messageToEncrypt.value, encryptionPublicKey.value)
    serializedSecret.value = JSON.stringify(encryptedSecret.value)
  } catch (error) {
    console.error('Error encrypting message:', error)
    alert('Failed to encrypt message')
  }
}

async function decryptMessage() {
  try {
    if (!decryptionPrivateKey.value || !secretToDecrypt.value) {
      alert('Please provide both private key and encrypted secret')
      return
    }

    decryptedMessage.value = await decrypt(
      secretToDecrypt.value,
      decryptionPrivateKey.value,
      decryptionPassphrase.value || undefined
    )
  } catch (error) {
    console.error('Error decrypting message:', error)
    alert('Failed to decrypt message')
  }
}
</script>
