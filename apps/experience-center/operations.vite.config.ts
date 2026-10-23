import {defineConfig} from 'vite';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=dirname(fileURLToPath(import.meta.url));
export default defineConfig({root,build:{outDir:'dist',emptyOutDir:false,rollupOptions:{input:{
 b2b:resolve(root,'b2b.html'),onboarding:resolve(root,'onboarding.html'),authorization:resolve(root,'authorization.html'),evidenceLab:resolve(root,'evidence-lab.html')
}}}});
