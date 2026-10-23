import {defineConfig, loadEnv} from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({mode}) => {
  // This server-side value is never published via import.meta.env.
  const env = loadEnv(mode, '.', '');
  const bffTarget = env.BFF_PROXY_TARGET || 'http://127.0.0.1:4100';
  return {
    plugins: [react()],
    server: {
      host: '0.0.0.0', port: 5173, strictPort: true,
      proxy: {'/api': bffTarget, '/auth': bffTarget, '/oidc': bffTarget},
    },
  };
});
