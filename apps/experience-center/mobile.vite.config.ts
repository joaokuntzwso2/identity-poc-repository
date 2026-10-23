import {defineConfig} from 'vite';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=dirname(fileURLToPath(import.meta.url));
// Separate HTML/React entry points = independent future OIDC clients.
// Reusing components does NOT merge mobile clients, issuers or sessions.
export default defineConfig({root,build:{outDir:'dist',emptyOutDir:false,rollupOptions:{input:{
  auroraMobile:resolve(root,'aurora-mobile.html'),brisaMobile:resolve(root,'brisa-mobile.html')
}}}});
