(() => {
  // local/session storage
  try { localStorage && localStorage.clear(); } catch {}
  try { sessionStorage && sessionStorage.clear(); } catch {}

  // Cache Storage (best-effort)
  (async () => {
    try {
      if (self.caches && caches.keys) {
        const keys = await caches.keys();
        await Promise.all(keys.map(k => caches.delete(k)));
      }
    } catch {}
  })();

  // IndexedDB cleanup
  try {
    if (self.indexedDB && typeof indexedDB.databases === "function") {
      indexedDB.databases().then(dbs => {
        for (const db of dbs || []) {
          try { db && db.name && indexedDB.deleteDatabase(db.name); } catch {}
        }
      });
    }
  } catch {}
})();
