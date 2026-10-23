import {defineConfig} from 'vite';
import {resolve,dirname} from 'node:path';
import {fileURLToPath} from 'node:url';
const root=dirname(fileURLToPath(import.meta.url));
export default defineConfig({root,build:{outDir:'dist',emptyOutDir:false,rollupOptions:{input:{wso2Lab:resolve(root,'wso2-lab.html')}}}});
