import { defineConfig, Plugin } from 'vite';
import { resolve } from 'path';
import { nodeExternals } from 'rollup-plugin-node-externals';

function externals(): Plugin {
  return {
    ...nodeExternals({
      deps: false,
      devDeps: false,
      peerDeps: false,
      optDeps: false,
    }),
    name: 'node-externals',
    enforce: 'pre',
    apply: 'build',
  }
}


export default defineConfig({
  build: {
    lib: {
      entry: resolve(__dirname, 'cli/index.ts'),
      formats: ['cjs'], // uniquement CommonJS
      fileName: () => 'letsdecrypt.js'
    },
    rollupOptions: {
      output: {
        globals: {
          //'node:fs': 'fs'
        }
      }
    }
  },
  plugins: [externals()]
})
