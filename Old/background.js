const COOKIE_NAME    = "reddit_session";
const REDDIT_DOMAINS = ["https://www.reddit.com/", "https://reddit.com/"];
let cryptoKey = null;

initCrypto();

async function initCrypto() {
  const { rawKey } = await chrome.storage.local.get("rawKey");
  if (rawKey) {
    const bytes = Uint8Array.from(atob(rawKey), c => c.charCodeAt(0));
    cryptoKey = await crypto.subtle.importKey(
      "raw", bytes, { name: "AES-GCM" }, false, ["encrypt","decrypt"]
    );
  } else {
    cryptoKey = await crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]
    );
    const raw = await crypto.subtle.exportKey("raw", cryptoKey);
    await chrome.storage.local.set({
      rawKey: btoa(String.fromCharCode(...new Uint8Array(raw)))
    });
  }
}

// handle keyboard shortcuts
chrome.commands.onCommand.addListener(async (cmd) => {
  if (!cmd.startsWith("switch-")) return;
  if (!cryptoKey) await initCrypto();

  const idx = parseInt(cmd.split("-")[1], 10) - 1;
  const { sessions = {}, order = Object.keys(sessions) } =
    await chrome.storage.local.get(["sessions","order"]);
  const name = order[idx];
  if (!name) return;

  await performSwitch(name);
  // trigger reload.js in-page reload
  await chrome.storage.local.set({ lastSwitched: Date.now() });
});

// handle popup “Switch” button
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.action === "switch-account" && msg.name) {
    performSwitch(msg.name).then(async () => {
      await chrome.storage.local.set({ lastSwitched: Date.now() });
    });
  }
});

async function decryptText(data) {
  const raw = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  const iv  = raw.slice(0,12), ct = raw.slice(12);
  const pt  = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv }, cryptoKey, ct
  );
  return new TextDecoder().decode(pt);
}

async function performSwitch(name) {
  const { sessions = {} } = await chrome.storage.local.get("sessions");
  const entry = sessions[name];
  if (!entry) return;

  const val = await decryptText(entry.enc);
  await Promise.all(REDDIT_DOMAINS.map(async (url) => {
    await chrome.cookies.remove({ url, name: COOKIE_NAME });
    await chrome.cookies.set({
      url,
      name: COOKIE_NAME,
      value: val,
      domain: ".reddit.com",
      path: "/",
      secure: true,
      httpOnly: true
    });
  }));
}
