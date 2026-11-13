import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import { defineConfig } from 'vite'

// https://vite.dev/config/
export default defineConfig({
  plugins: [svelte(), tailwindcss(), viteSingleFile()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://127.0.0.1:3030',
    },
  },
  build: {
    outDir: '../dist',
    emptyOutDir: true,
  },
})
