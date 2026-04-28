const HOSTS = [
  "reddit.com", "www.reddit.com", "old.reddit.com", "mod.reddit.com",
  "oauth.reddit.com", "gateway.reddit.com"
];

const list       = document.getElementById("accountsList");
const modal      = document.getElementById("editModal");
const editInput  = document.getElementById("editInput");
const confirmBtn = document.getElementById("confirmEdit");
const cancelBtn  = document.getElementById("cancelEdit");
const donateOnceModal = document.getElementById("donateOnceModal");
const donateOnceOk    = document.getElementById("donateOnceOk");
const saveHelpModal = document.getElementById("saveHelpModal");
const saveHelpDontShow = document.getElementById("saveHelpDontShow");
const saveHelpContinue = document.getElementById("saveHelpContinue");
const saveHelpCancel = document.getElementById("saveHelpCancel");

const delModal   = document.getElementById("deleteModal");
const delMsg     = document.getElementById("deleteMsg");
const delYesBtn  = document.getElementById("confirmDelete");
const delNoBtn   = document.getElementById("cancelDelete");

let cryptoKey = null;
let currentEdit = null;
let pendingDelete = null;

// NEW: cached setting
let closeAfterSwitch = false;
async function showDonateOnceIfNeeded(){
  if (!donateOnceModal) return;

  const { donateOnceSeen } = await chrome.storage.local.get("donateOnceSeen");
  if (donateOnceSeen) return;

  const close = async () => {
    donateOnceModal.classList.add("hidden");
    await chrome.storage.local.set({ donateOnceSeen: true });
  };

  donateOnceModal.classList.remove("hidden");

  // close by button
  donateOnceOk?.addEventListener("click", close, { once: true });

  // close by clicking backdrop
  donateOnceModal.addEventListener("click", (e) => {
    if (e.target === donateOnceModal) close();
  }, { once: true });

  // close by Escape
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && !donateOnceModal.classList.contains("hidden")) close();
  }, { once: true });
}

document.addEventListener("DOMContentLoaded", async () => {
  // Settings
  await showDonateOnceIfNeeded();

  const settingsBtn = document.getElementById("openSettings");
  if (settingsBtn) {
    settingsBtn.onclick = () => {
      if (chrome.runtime.openOptionsPage) chrome.runtime.openOptionsPage();
      else window.open(chrome.runtime.getURL("settings.html"), "_blank");
    };
  }

  // NEW: load close setting + keep it updated live
  try {
    const st = await chrome.storage.local.get("closeOnSwitch");
    closeAfterSwitch = !!st.closeOnSwitch;
  } catch {
    closeAfterSwitch = false;
  }

  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "local" && changes.closeOnSwitch) {
      closeAfterSwitch = !!changes.closeOnSwitch.newValue;
    }
  });

  await initCrypto();
  await maybeMigrateOldData();

  const saveBtn = document.getElementById("saveBtn");
  if (saveBtn) saveBtn.onclick = saveAccountWithWarning;
  if (saveHelpContinue) saveHelpContinue.onclick = continueSaveAfterWarning;
  if (saveHelpCancel) saveHelpCancel.onclick = closeSaveHelp;
  saveHelpModal?.addEventListener("click", (e) => {
    if (e.target === saveHelpModal) closeSaveHelp();
  });

  if (confirmBtn) confirmBtn.onclick = applyEdit;
  if (cancelBtn)  cancelBtn.onclick  = () => modal?.classList.add("hidden");

  if (delYesBtn) delYesBtn.onclick = async () => {
    if (pendingDelete) await reallyDeleteAccount(pendingDelete);
    closeDeleteConfirm();
  };
  if (delNoBtn) delNoBtn.onclick = closeDeleteConfirm;

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") {
      modal?.classList.add("hidden");
      delModal?.classList.add("hidden");
      saveHelpModal?.classList.add("hidden");
    }
  });

  await loadAccounts();
});

/* ===================== Crypto helpers (device key) ===================== */
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

async function encryptBytes(bytes) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, cryptoKey, bytes);
  const buf = new Uint8Array(iv.byteLength + ct.byteLength);
  buf.set(iv,0);
  buf.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}
async function decryptToBytes(b64) {
  const raw = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  const iv  = raw.slice(0,12);
  const ct  = raw.slice(12);
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, cryptoKey, ct);
  return new Uint8Array(pt);
}
async function encryptJSON(obj){
  const enc = new TextEncoder().encode(JSON.stringify(obj));
  return encryptBytes(enc);
}
async function decryptJSON(b64){
  const bytes = await decryptToBytes(b64);
  return JSON.parse(new TextDecoder().decode(bytes));
}

/* ===================== Storage schema =====================
chrome.storage.local:
{
  schemaVersion: 2,
  profiles: {
    "<id>": {
      name: "My alt",
      encCookies: "<b64>",      // encrypted JSON array of cookie objects
      createdAt: 1710000000000,
      updatedAt: 1710000000000,
      tags?: string[],
      note?: string
    }
  },
  order: ["<id>", ...],
  hiddenStates: { "<id>": true|false },
  activeProfileId: "<id>" | undefined,
  closeOnSwitch: true|false,
  reloadActiveTabOnly: true|false,
  saveHelpDontShowAgain: true|false
}
=========================================================== */

function uid() {
  const a = crypto.getRandomValues(new Uint32Array(3));
  return [...a].map(x => x.toString(36)).join("-");
}

async function getState() {
  const def = {
    schemaVersion: 2,
    profiles:{},
    order:[],
    hiddenStates:{},
    activeProfileId: undefined,
    closeOnSwitch: false,
    reloadActiveTabOnly: false,
    saveHelpDontShowAgain: false
  };
  const got = await chrome.storage.local.get([
    "schemaVersion",
    "profiles",
    "order",
    "hiddenStates",
    "activeProfileId",
    "closeOnSwitch",
    "reloadActiveTabOnly",
    "saveHelpDontShowAgain"
  ]);
  return Object.assign(def, got);
}

async function setState(patch){
  const now = Date.now();
  if (patch.profiles) {
    for (const id of Object.keys(patch.profiles)) {
      const v = patch.profiles[id];
      if (v && typeof v === "object") {
        if (!v.createdAt) v.createdAt = now;
        v.updatedAt = now;
      }
    }
  }
  await chrome.storage.local.set(Object.assign({ schemaVersion: 2 }, patch));
}

/* ===================== Migration (v1 -> v2) ===================== */
async function maybeMigrateOldData() {
  const { sessions, order, hiddenStates, schemaVersion } =
    await chrome.storage.local.get(["sessions","order","hiddenStates","schemaVersion"]);

  if (schemaVersion >= 2) return;

  const profiles = {};
  const newOrder = [];

  if (sessions && typeof sessions === "object") {
    for (const name of Object.keys(sessions)) {
      const entry = sessions[name];
      const id = uid();

      let encCookies;
      try {
        const dec = await decryptJSON(entry.enc);
        encCookies = Array.isArray(dec) ? await encryptJSON(dec) : null;
      } catch {
        encCookies = null;
      }

      if (!encCookies) {
        // legacy: treat as single reddit_session value
        try {
          const bytes = await decryptToBytes(entry.enc);
          const value = new TextDecoder().decode(bytes);
          encCookies = await encryptJSON([{
            name: "reddit_session",
            value,
            domain: ".reddit.com",
            path: "/",
            secure: true,
            httpOnly: true
          }]);
        } catch {}
      }

      profiles[id] = { name, encCookies, createdAt: Date.now(), updatedAt: Date.now() };
      newOrder.push(id);
    }
  }

  const newHidden = {};
  if (hiddenStates) {
    for (let i = 0; i < (order||[]).length; i++) {
      const oldName = order[i];
      const id = newOrder[i];
      if (id && oldName in hiddenStates) newHidden[id] = !!hiddenStates[oldName];
    }
  }

  await chrome.storage.local.remove(["sessions","hiddenStates","order"]);
  await setState({ profiles, order: newOrder, hiddenStates: newHidden, schemaVersion: 2 });
}

/* ===================== Cookie capture (FIXED) ===================== */
function cookieKey(c){
  return `${c.name}|${c.domain}|${c.path||"/"}`;
}

async function collectRedditCookies(){
  const lists = await Promise.all([
    chrome.cookies.getAll({ domain: ".reddit.com" }),
    chrome.cookies.getAll({ domain: "reddit.com" }),
    ...HOSTS.map(h => chrome.cookies.getAll({ url: `https://${h}/` }))
  ]);

  const map = new Map();
  for (const arr of lists) {
    for (const c of (arr || [])) map.set(cookieKey(c), c);
  }

  return [...map.values()];
}

/* ===================== Save ===================== */
async function saveAccountWithWarning() {
  const nameEl = document.getElementById("accountName");
  const name = (nameEl?.value || "").trim();
  if (!name) return saveAccount();

  const { saveHelpDontShowAgain } = await chrome.storage.local.get("saveHelpDontShowAgain");
  if (saveHelpDontShowAgain) return saveAccount();

  openSaveHelp();
}

function openSaveHelp() {
  if (!saveHelpModal) return saveAccount();
  if (saveHelpDontShow) saveHelpDontShow.checked = false;
  saveHelpModal.classList.remove("hidden");
  saveHelpContinue?.focus();
}

function closeSaveHelp() {
  saveHelpModal?.classList.add("hidden");
}

async function continueSaveAfterWarning() {
  if (saveHelpDontShow?.checked) {
    await chrome.storage.local.set({ saveHelpDontShowAgain: true });
  }
  closeSaveHelp();
  await saveAccount();
}

async function saveAccount() {
  const nameEl = document.getElementById("accountName");
  const name = (nameEl?.value || "").trim();
  if (!name) return;

  const cookies = await collectRedditCookies();
  if (!cookies.length) {
    alert("No Reddit cookies found. Log in to Reddit, then try again.");
    return;
  }

  const encCookies = await encryptJSON(cookies);

  const state = await getState();
  const id = uid();

  state.profiles[id] = { name, encCookies, createdAt: Date.now(), updatedAt: Date.now() };
  state.order.push(id);

  await setState({ profiles: state.profiles, order: state.order });
  if (nameEl) nameEl.value = "";
  await loadAccounts();
}

/* ===================== Delete / Rename ===================== */
async function reallyDeleteAccount(profileId) {
  const state = await getState();

  delete state.profiles[profileId];
  delete state.hiddenStates[profileId];

  const i = state.order.indexOf(profileId);
  if (i > -1) state.order.splice(i,1);

  if (state.activeProfileId === profileId) delete state.activeProfileId;

  await setState({
    profiles: state.profiles,
    order: state.order,
    hiddenStates: state.hiddenStates,
    activeProfileId: state.activeProfileId
  });
  await loadAccounts();
}

function openDeleteConfirm(profileId, name) {
  pendingDelete = profileId;
  if (delMsg) delMsg.textContent = `Delete “${name}”? This cannot be undone.`;
  delModal?.classList.remove("hidden");
}

function closeDeleteConfirm() {
  pendingDelete = null;
  delModal?.classList.add("hidden");
}

function startEdit(profileId, name) {
  currentEdit = profileId;
  if (editInput) editInput.value = name;
  modal?.classList.remove("hidden");
  editInput?.focus();
}

async function applyEdit() {
  const newName = (editInput?.value || "").trim();
  if (!newName || !currentEdit) {
    modal?.classList.add("hidden");
    return;
  }

  const state = await getState();
  const p = state.profiles[currentEdit];
  if (p) p.name = newName;

  await setState({ profiles: state.profiles });
  currentEdit = null;
  modal?.classList.add("hidden");
  await loadAccounts();
}

/* ===================== Visibility toggle (LIGHTWEIGHT) ===================== */
async function toggleVisibility(li, span, btn) {
  const id   = li.dataset.id;
  const name = li.dataset.name;

  const hidden = li.dataset.hidden !== "true";
  li.dataset.hidden = hidden;

  span.textContent = hidden ? "•".repeat(name.length) : name;
  btn.textContent  = hidden ? "𓂋" : "👁";
  btn.title        = hidden ? "Show name" : "Hide name";

  // only fetch/write hiddenStates (fast)
  const got = await chrome.storage.local.get("hiddenStates");
  const hs = (got.hiddenStates && typeof got.hiddenStates === "object") ? got.hiddenStates : {};
  hs[id] = hidden;
  await chrome.storage.local.set({ hiddenStates: hs });
}

/* ===================== Switch (FIXED + close option) ===================== */
async function switchTo(profileId){
  try{
    const res = await new Promise((resolve, reject)=>{
      chrome.runtime.sendMessage({ cmd: "uswitch:switch", profileId }, (resp)=>{
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        resolve(resp);
      });
    });

    if (!res || !res.ok) throw new Error(res?.err || "Switch failed");

    // NEW: close popup after switching (if enabled)
    if (closeAfterSwitch) window.close();

  } catch(e){
    alert("Switch error: " + (e?.message || e));
  }
}

/* ===================== Render list ===================== */
async function loadAccounts() {
  if (!list) return;

  const state = await getState();
  list.innerHTML = "";

  for (const id of state.order) {
    const entry = state.profiles[id];
    if (!entry) continue;

    const li = document.createElement("li");
    li.dataset.id   = id;
    li.dataset.name = entry.name;
    const hf = !!state.hiddenStates[id];
    li.dataset.hidden = hf;
    li.draggable = true;

    const handle = document.createElement("span");
    handle.className = "drag-handle";
    handle.textContent = "≡";
    li.append(handle);

    const span = document.createElement("span");
    span.className = "account-name";
    span.textContent = hf ? "•".repeat(entry.name.length) : entry.name;

    const eyeBtn = document.createElement("button");
    eyeBtn.textContent = hf ? "𓂋" : "👁";
    eyeBtn.title = hf ? "Show name" : "Hide name";
    eyeBtn.onclick = () => toggleVisibility(li, span, eyeBtn);

    const editBtn = document.createElement("button");
    editBtn.textContent = "🖊";
    editBtn.title = "Rename";
    editBtn.onclick = () => startEdit(id, entry.name);

    const swBtn = document.createElement("button");
    swBtn.textContent = "Switch";
    swBtn.title = "Switch to this account";
    swBtn.onclick = () => switchTo(id);

    const dlBtn = document.createElement("button");
    dlBtn.textContent = "Delete";
    dlBtn.title = "Delete this account";
    dlBtn.onclick = () => openDeleteConfirm(id, entry.name);

    li.append(span, eyeBtn, editBtn, swBtn, dlBtn);

    // drag & drop (reorder by id)
    li.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", id);
      e.dropEffect = "move";
    });
    li.addEventListener("dragover", e => { e.preventDefault(); li.classList.add("drag-over"); });
    li.addEventListener("dragleave", () => li.classList.remove("drag-over"));
    li.addEventListener("drop", async e => {
      e.preventDefault();
      li.classList.remove("drag-over");

      const from = e.dataTransfer.getData("text/plain");
      if (from && from !== id) {
        const st2 = await getState();
        const iFrom = st2.order.indexOf(from);
        const iTo   = st2.order.indexOf(id);

        if (iFrom > -1 && iTo > -1) {
          st2.order.splice(iFrom,1);
          st2.order.splice(iTo,0,from);
          await setState({ order: st2.order });
          await loadAccounts();
        }
      }
    });

    list.append(li);
  }
}
