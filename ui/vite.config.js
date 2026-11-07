import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'

// El backend (FastAPI) corre en el 8100; la API simulada de Deloitte en el 8000.
export default defineConfig({
  plugins: [vue()],
  server: { port: 5173, proxy: { '/api': 'http://localhost:8100' } },
})
