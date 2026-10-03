import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';
import fs from 'node:fs';
import path from 'node:path';

// Custom Vite plugin to serve the parent ../data directory under /data
function serveDataDirectory() {
  return {
    name: 'serve-parent-data',
    configureServer(server) {
      server.middlewares.use('/data', (req, res, next) => {
        try {
          const rawUrl = req.url.split('?')[0];
          const decodedPath = decodeURIComponent(rawUrl.replace(/^\//, ''));
          const targetFile = path.resolve(__dirname, '..', 'data', decodedPath);

          // Serve only sanitized analysis/output data. Raw app captures under
          // data/apps may contain personal information and are never exposed.
          const dataDir = path.resolve(__dirname, '..', 'data');
          const relativeToData = path.relative(dataDir, targetFile);
          const topLevelDirectory = relativeToData.split(path.sep)[0];
          if (
            relativeToData.startsWith('..') ||
            path.isAbsolute(relativeToData) ||
            !['analysis', 'output'].includes(topLevelDirectory)
          ) {
            res.statusCode = 403;
            return res.end('Access denied');
          }

          if (fs.existsSync(targetFile) && fs.statSync(targetFile).isFile()) {
            const ext = path.extname(targetFile).toLowerCase();
            const mimeTypes = {
              '.json': 'application/json; charset=utf-8',
              '.csv': 'text/csv; charset=utf-8',
              '.txt': 'text/plain; charset=utf-8',
              '.har': 'application/json; charset=utf-8'
            };
            res.setHeader('Content-Type', mimeTypes[ext] || 'application/octet-stream');
            const stream = fs.createReadStream(targetFile);
            return stream.pipe(res);
          }
          next();
        } catch (err) {
          console.error('[serveDataDirectory] Error:', err);
          next();
        }
      });
    }
  };
}

export default defineConfig({
  plugins: [react(), serveDataDirectory()],
  server: {
    port: 5173,
    host: 'localhost',
    fs: {
      allow: ['..']
    }
  }
});
