  // sw.js
  // 🏁 Hidden flag
  console.log("Flag: THMxHYDPY{h1dd3n_1n_s3rv1c3_w0rk3r}");

  // Dummy service worker to keep it alive
  self.addEventListener('install', (e) => {
    self.skipWaiting();
  });

  self.addEventListener('activate', (e) => {
    clients.claim();
  });
