import { svelte } from '@sveltejs/vite-plugin-svelte'
import tailwindcss from '@tailwindcss/vite'
import { viteSingleFile } from 'vite-plugin-singlefile'
import { defineConfig, type Plugin } from 'vite'

function moveInlineModuleScriptToBodyEnd(): Plugin {
  return {
    name: 'aether-move-inline-script-to-body-end',
    enforce: 'post',
    generateBundle(_options, bundle) {
      for (const file of Object.values(bundle)) {
        if (file.type === 'asset' && file.fileName.endsWith('.html') && typeof file.source === 'string') {
          const html = file.source;
          const headEnd = html.indexOf('</head>');
          const scriptMatch = html.match(/<script type="module"[^>]*>[\s\S]*?<\/script>/);
          if (scriptMatch && headEnd > 0 && (scriptMatch.index ?? 0) < headEnd) {
            const scriptTag = scriptMatch[0];
            const withoutHeadScript = html.slice(0, scriptMatch.index!) + html.slice(scriptMatch.index! + scriptTag.length);
            const appDiv = '<div id="app"></div>';
            const appPos = withoutHeadScript.lastIndexOf(appDiv);
            if (appPos >= 0) {
              const insertPos = appPos + appDiv.length;
              file.source = withoutHeadScript.slice(0, insertPos) + '\n    ' + scriptTag + withoutHeadScript.slice(insertPos);
            }
          }
        }
      }
    },
  }
}

// https://vite.dev/config/
export default defineConfig({
  base: './',
  plugins: [svelte(), tailwindcss(), viteSingleFile(), moveInlineModuleScriptToBodyEnd()],
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
