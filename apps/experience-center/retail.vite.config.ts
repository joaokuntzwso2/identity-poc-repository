import {defineConfig} from 'vite';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=dirname(fileURLToPath(import.meta.url));
export default defineConfig({root,build:{outDir:'dist',emptyOutDir:false,rollupOptions:{input:{aurora:resolve(root,'aurora.html'),brisa:resolve(root,'brisa.html')}}}});
