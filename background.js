const HOSTS = [
  "reddit.com", "www.reddit.com", "old.reddit.com",
  "mod.reddit.com", "oauth.reddit.com", "gateway.reddit.com"
];

let cryptoKey = null;

// ===== Boot =====
initCrypto();

async function initCrypto() {
  let { rawKey } = await chrome.storage.local.get("rawKey");
  if (!rawKey) {
    const raw = crypto.getRandomValues(new Uint8Array(32));
    rawKey = btoa(String.fromCharCode(...raw));
    await chrome.storage.local.set({ rawKey });
  }
  cryptoKey = await crypto.subtle.importKey(
    "raw",
    Uint8Array.from(atob(rawKey), c => c.charCodeAt(0)),
    { name: "AES-GCM" },
    false,
    ["encrypt","decrypt"]
  );
}

// ===== Helpers =====
async function decryptToBytes(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv  = raw.slice(0,12), ct = raw.slice(12);
  const pt  = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, cryptoKey, ct);
  return new Uint8Array(pt);
}
async function decryptJSON(b64) {
  const bytes = await decryptToBytes(b64);
  return JSON.parse(new TextDecoder().decode(bytes));
}

const urlForCookie = (c) => {
  const proto = c.secure ? "https://" : "http://";
  const host  = (c.domain || "reddit.com").replace(/^\./, "");
  const path  = c.path || "/";
  return proto + host + path;
};

async function getState() {
  const def = {
    schemaVersion: 2,
    profiles:{},
    order:[],
    hiddenStates:{},
    activeProfileId: undefined,
    reloadActiveTabOnly: false
  };
  const got = await chrome.storage.local.get([
    "schemaVersion",
    "profiles",
    "order",
    "hiddenStates",
    "activeProfileId",
    "reloadActiveTabOnly"
  ]);
  return Object.assign(def, got);
}

// Clear cookies across all relevant Reddit hosts (de-duped by name|domain|path)
async function clearRedditCookies() {
  const lists = await Promise.all([
    chrome.cookies.getAll({ domain: ".reddit.com" }),
    chrome.cookies.getAll({ domain: "reddit.com" }),
    ...HOSTS.map(h => chrome.cookies.getAll({ url: "https://" + h + "/" }))
  ]);

  const seen = new Map();
  for (const arr of lists) {
    for (const c of (arr || [])) {
      const k = `${c.name}|${c.domain}|${c.path || "/"}`;
      if (!seen.has(k)) seen.set(k, c);
    }
  }

  await Promise.allSettled(
    [...seen.values()].map(c => chrome.cookies.remove({ url: urlForCookie(c), name: c.name }))
  );
}

async function setCookies(cookies) {
  for (const c of cookies) {
    const details = {
      url: urlForCookie(c),
      name: c.name,
      value: c.value,
      domain: c.domain,
      path: c.path || "/",
      secure: !!c.secure,
      httpOnly: !!c.httpOnly,
      sameSite: c.sameSite || "no_restriction"
    };
    if (!c.session && c.expirationDate) details.expirationDate = c.expirationDate;
    await chrome.cookies.set(details);
  }
}

async function reloadRedditTabs() {
  const { reloadActiveTabOnly } = await chrome.storage.local.get("reloadActiveTabOnly");

  if (reloadActiveTabOnly) {
    const [activeTab] = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
    if (activeTab?.id && /^https?:\/\/([^/]+\.)?reddit\.com\//i.test(activeTab.url || "")) {
      await chrome.tabs.reload(activeTab.id);
    }
    return;
  }

  const tabs = await chrome.tabs.query({ url: ["*://*.reddit.com/*"] });
  await Promise.allSettled(tabs.map(t => chrome.tabs.reload(t.id)));
}

// ===== Core switch by profileId =====
async function switchTo(profileId) {
  if (!cryptoKey) await initCrypto();

  // simple lock to avoid racing clicks/commands
  const lock = await chrome.storage.session.get("switchLock");
  if (lock.switchLock) return;
  await chrome.storage.session.set({ switchLock: true });

  try {
    const state = await getState();
    const prof = state.profiles[profileId];
    if (!prof) throw new Error("Profile not found");

    const cookies = await decryptJSON(prof.encCookies);
    if (!Array.isArray(cookies) || cookies.length === 0) {
      throw new Error("No cookies in profile");
    }

    await clearRedditCookies();
    await setCookies(cookies);

    await chrome.storage.local.set({ activeProfileId: profileId, lastSwitchAt: Date.now() });
    await reloadRedditTabs();
  } finally {
    await chrome.storage.session.remove("switchLock");
  }
}

// ===== Messages from popup =====
chrome.runtime.onMessage.addListener((msg, _sender, send) => {
  (async () => {
    if (msg?.cmd === "uswitch:switch" && msg.profileId) {
      try {
        await switchTo(msg.profileId);
        send({ ok: true });
      } catch (e) {
        send({ ok: false, err: String(e && e.message || e) });
      }
      return;
    }
    send({ ok: false, err: "Unknown command" });
  })();
  return true;
});

// ===== Keyboard shortcuts: "switch-1" … "switch-4" =====
chrome.commands.onCommand.addListener(async (cmd) => {
  if (!cmd || !cmd.startsWith("switch-")) return;
  const idx = Math.max(0, parseInt(cmd.split("-")[1], 10) - 1);
  const state = await getState();
  const id = state.order[idx];
  if (id) await switchTo(id);
});
