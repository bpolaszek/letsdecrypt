<template>
  <div class="container mx-auto p-4">
    <h1 class="text-2xl font-bold mb-6">Crypto Library Demo</h1>

    <!-- Key Generation -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Generate Key Pair</h2>
      <div class="space-y-4">
        <div>
          <label class="block mb-2">Passphrase (optional)</label>
          <input
            v-model="passphrase"
            type="password"
            class="border p-2 rounded w-full"
            placeholder="Enter passphrase"
          />
        </div>
        <button
          @click="generateKeyPair"
          class="bg-blue-500 text-white px-4 py-2 rounded"
        >
          Generate Keys
        </button>
      </div>

      <div v-if="keyPair" class="mt-4 space-y-4">
        <div>
          <label class="block mb-2">Public Key</label>
          <textarea
            v-model="serializedKeys.publicKey"
            readonly
            class="border p-2 rounded w-full h-32"
          ></textarea>
        </div>
        <div>
          <label class="block mb-2">Private Key</label>
          <textarea
            v-model="serializedKeys.privateKey"
            readonly
            class="border p-2 rounded w-full h-32"
          ></textarea>
        </div>
      </div>
    </section>

    <!-- Encryption -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Encrypt Message</h2>
      <div class="space-y-4">
        <div>
          <label class="block mb-2">Public Key</label>
          <textarea
            v-model="encryptionPublicKey"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste public key here"
          ></textarea>
        </div>
        <div>
          <label class="block mb-2">Message to Encrypt</label>
          <textarea
            v-model="messageToEncrypt"
            class="border p-2 rounded w-full h-32"
            placeholder="Enter message to encrypt"
          ></textarea>
        </div>
        <button
          @click="encryptMessage"
          class="bg-green-500 text-white px-4 py-2 rounded"
        >
          Encrypt
        </button>
      </div>

      <div v-if="encryptedSecret" class="mt-4">
        <label class="block mb-2">Encrypted Secret</label>
        <textarea
          v-model="serializedSecret"
          readonly
          class="border p-2 rounded w-full h-32"
        ></textarea>
      </div>
    </section>

    <!-- Decryption -->
    <section class="mb-8">
      <h2 class="text-xl font-semibold mb-4">Decrypt Message</h2>
      <div class="space-y-4">
        <div>
          <label class="block mb-2">Private Key</label>
          <textarea
            v-model="decryptionPrivateKey"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste private key here"
          ></textarea>
        </div>
        <div>
          <label class="block mb-2">Passphrase (if required)</label>
          <input
            v-model="decryptionPassphrase"
            type="password"
            class="border p-2 rounded w-full"
            placeholder="Enter passphrase"
          />
        </div>
        <div>
          <label class="block mb-2">Encrypted Secret</label>
          <textarea
            v-model="secretToDecrypt"
            class="border p-2 rounded w-full h-32"
            placeholder="Paste encrypted secret here"
          ></textarea>
        </div>
        <button
          @click="decryptMessage"
          class="bg-purple-500 text-white px-4 py-2 rounded"
        >
          Decrypt
        </button>
      </div>

      <div v-if="decryptedMessage" class="mt-4">
        <label class="block mb-2">Decrypted Message</label>
        <textarea
          v-model="decryptedMessage"
          readonly
          class="border p-2 rounded w-full h-32"
        ></textarea>
      </div>
    </section>
  </div>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { CryptoService, type SerializedKeyPair } from '~/utils/crypto'

// Key Generation
const passphrase = ref('')
const keyPair = ref<CryptoKeyPair | null>(null)
const serializedKeys = ref<SerializedKeyPair>({ publicKey: '', privateKey: '' })

// Encryption
const encryptionPublicKey = ref('')
const messageToEncrypt = ref('')
const encryptedSecret = ref<Secret | null>(null)
const serializedSecret = ref('')

// Decryption
const decryptionPrivateKey = ref('')
const decryptionPassphrase = ref('')
const secretToDecrypt = ref('')
const decryptedMessage = ref('')

async function generateKeyPair() {
  try {
    console.log(passphrase.value)
    keyPair.value = await CryptoService.generateKeyPair({
      passphrase: passphrase.value || undefined,
    })
    serializedKeys.value = await CryptoService.exportKeyPair(keyPair.value)
  } catch (error) {
    console.error('Error generating key pair:', error)
    alert('Failed to generate key pair')
  }
}

async function encryptMessage() {
  try {
    if (!encryptionPublicKey.value || !messageToEncrypt.value) {
      alert('Please provide both public key and message')
      return
    }

    encryptedSecret.value = await CryptoService.encrypt(
      messageToEncrypt.value,
      encryptionPublicKey.value
    )
    serializedSecret.value = encryptedSecret.value.serialize()
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

    decryptedMessage.value = await CryptoService.decrypt(
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
