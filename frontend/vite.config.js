import { defineConfig } from 'vite'
import fs from 'fs'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '10.12.30.13',
    port: 443,
    https: {
      key: fs.readFileSync('nginx-selfsigned.key'),
      cert: fs.readFileSync('nginx-selfsigned.crt'),
    }
  }
})
