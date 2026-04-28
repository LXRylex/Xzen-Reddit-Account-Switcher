(() => {
  const KEY = "__uswitch_lastSeen__";
  const SAFE_DELAY_MS = 800; // prevent double reloads

  async function clearCaches() {
    try { localStorage && localStorage.clear(); } catch {}
    try { sessionStorage && sessionStorage.clear(); } catch {}
    try {
      if (self.caches && caches.keys) {
        const keys = await caches.keys();
        await Promise.all(keys.map(k => caches.delete(k)));
      }
    } catch {}
    try {
      if (self.indexedDB && typeof indexedDB.databases === "function") {
        const dbs = await indexedDB.databases();
        for (const db of dbs || []) {
          try { db && db.name && indexedDB.deleteDatabase(db.name); } catch {}
        }
      }
    } catch {}
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area !== "local") return;

    const change = changes.lastSwitchAt || changes.lastSwitched;
    if (!change) return;

    chrome.storage.local.get("reloadActiveTabOnly", ({ reloadActiveTabOnly }) => {
      // Dev Note: In active tab only mode, the background worker reloads the active Reddit tab.
      if (reloadActiveTabOnly) return;

      const ts = Number(change.newValue || 0);
      const last = Number(sessionStorage.getItem(KEY) || 0);
      if (!ts || ts <= last) return;

      sessionStorage.setItem(KEY, String(ts));

      const doReload = async () => {
        await clearCaches();
        setTimeout(() => window.location.reload(), SAFE_DELAY_MS);
      };

      if (document.visibilityState === "visible") {
        doReload();
      } else {
        const onVis = () => {
          if (document.visibilityState === "visible") {
            document.removeEventListener("visibilitychange", onVis);
            doReload();
          }
        };
        document.addEventListener("visibilitychange", onVis);
      }
    });
  });
})();
