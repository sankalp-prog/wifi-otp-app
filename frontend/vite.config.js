import { defineConfig } from 'vite'
import fs from 'fs'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '10.40.13.182',
    port: 5000,
    https: {
      key: fs.readFileSync('nginx-selfsigned.key'),
      cert: fs.readFileSync('nginx-selfsigned.crt'),
    }
  }
})
