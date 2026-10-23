import {defineConfig} from 'vite';
// Local synthetic development: prevents legacy Vite catch-all proxy from sending
// independent entrypoints (e.g. /authorization.html) to a missing :4100 server.
// Serve all existing HTML entries directly, proxy only API calls to :4317.
export default defineConfig({
 server:{host:'127.0.0.1',port:5173,strictPort:true,
  proxy:{'/api/operator':{target:'http://127.0.0.1:4391',changeOrigin:false},'/api':{target:'http://127.0.0.1:4317',changeOrigin:false}}},
});
