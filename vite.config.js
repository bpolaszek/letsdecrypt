import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'path';

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [vue()],
  build: {
    lib: {
      entry: path.resolve(__dirname, 'src/index.ts'),
      name: 'letsdecrypt',
      fileName: (format) => `letsdecrypt.${format}.js`,
    },
    rollupOptions: {
      // createEndpoints sure to externalize deps that shouldn't be bundled
      // into your library
      external: ['buffer'],
      output: {
        exports: 'named',
        // Provide global variables to use in the UMD build
        // for externalized deps
        globals: {
          buffer: 'buffer',
        },
      },
    },
  },
});
