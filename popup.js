const COOKIE_NAME = "reddit_session";
const REDDIT_URL  = "https://www.reddit.com";
let cryptoKey = null, currentEdit = null;

const modal      = document.getElementById("editModal"),
      editInput  = document.getElementById("editInput"),
      confirmBtn = document.getElementById("confirmEdit"),
      cancelBtn  = document.getElementById("cancelEdit"),
      list       = document.getElementById("accountsList"),
      reloadAllTabsToggle = document.getElementById("reloadAllTabs");

document.addEventListener("DOMContentLoaded", async () => {
  await initCrypto();
  document.getElementById("saveBtn").onclick = saveAccount;
  confirmBtn.onclick = applyEdit;
  cancelBtn.onclick  = () => modal.classList.add("hidden");
  const { reloadAllTabs = true } = await chrome.storage.local.get("reloadAllTabs");
  reloadAllTabsToggle.checked = reloadAllTabs;
  reloadAllTabsToggle.onchange = async () => {
    await chrome.storage.local.set({ reloadAllTabs: reloadAllTabsToggle.checked });
  };
  loadAccounts();
});

async function initCrypto() {
  const { rawKey } = await chrome.storage.local.get("rawKey");
  if (rawKey) {
    cryptoKey = await crypto.subtle.importKey(
      "raw",
      Uint8Array.from(atob(rawKey), c => c.charCodeAt(0)),
      { name:"AES-GCM" },
      false,
      ["encrypt","decrypt"]
    );
  }
}

async function encryptText(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, cryptoKey, new TextEncoder().encode(text));
  const buf = new Uint8Array(iv.byteLength + ct.byteLength);
  buf.set(iv,0); buf.set(new Uint8Array(ct), iv.byteLength);
  return btoa(String.fromCharCode(...buf));
}

async function decryptText(data) {
  const raw = Uint8Array.from(atob(data), c => c.charCodeAt(0));
  const iv  = raw.slice(0,12), ct = raw.slice(12);
  const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, cryptoKey, ct);
  return new TextDecoder().decode(pt);
}

async function saveAccount() {
  const name = document.getElementById("accountName").value.trim();
  if (!name) return;
  const cookie = await chrome.cookies.get({ url:REDDIT_URL, name:COOKIE_NAME });
  if (!cookie) return alert("No reddit_session cookie");
  const enc = await encryptText(cookie.value);
  const { sessions={}, order=[], hiddenStates={} } = await chrome.storage.local.get(["sessions","order","hiddenStates"]);
  if (!sessions[name]) order.push(name);
  sessions[name] = { enc };
  await chrome.storage.local.set({ sessions, order, hiddenStates });
  loadAccounts();
}

async function deleteAccount(name) {
  const { sessions={}, order=[], hiddenStates={} } = await chrome.storage.local.get(["sessions","order","hiddenStates"]);
  delete sessions[name];
  delete hiddenStates[name];
  const idx = order.indexOf(name);
  if (idx>-1) order.splice(idx,1);
  await chrome.storage.local.set({ sessions, order, hiddenStates });
  loadAccounts();
}

function startEdit(name) {
  currentEdit = name;
  editInput.value = name;
  modal.classList.remove("hidden");
  editInput.focus();
}

async function applyEdit() {
  const newName = editInput.value.trim();
  if (!newName || newName===currentEdit) {
    modal.classList.add("hidden");
    return;
  }
  const { sessions={}, order=[], hiddenStates={} } = await chrome.storage.local.get(["sessions","order","hiddenStates"]);
  sessions[newName]     = sessions[currentEdit];
  hiddenStates[newName] = hiddenStates[currentEdit]||false;
  delete sessions[currentEdit];
  delete hiddenStates[currentEdit];
  const idx = order.indexOf(currentEdit);
  if (idx>-1) order[idx] = newName;
  await chrome.storage.local.set({ sessions, order, hiddenStates });
  currentEdit=null;
  modal.classList.add("hidden");
  loadAccounts();
}

async function toggleVisibility(li, span, btn) {
  const name   = li.dataset.name;
  const hidden = li.dataset.hidden!=="true";
  li.dataset.hidden = hidden;
  span.textContent  = hidden? "•".repeat(name.length): name;
  btn.textContent   = hidden? "𓂋":"👁";
  const { hiddenStates={} } = await chrome.storage.local.get("hiddenStates");
  hiddenStates[name] = hidden;
  await chrome.storage.local.set({ hiddenStates });
}

async function loadAccounts() {
  const { sessions={}, order=Object.keys(sessions), hiddenStates={} } = await chrome.storage.local.get(["sessions","order","hiddenStates"]);
  list.innerHTML = "";
  for (let name of order) {
    const entry = sessions[name];
    if (!entry) continue;
    const li = document.createElement("li");
    li.dataset.name   = name;
    const hf = !!hiddenStates[name];
    li.dataset.hidden = hf;
    li.draggable      = true;

    const handle = document.createElement("span");
    handle.className = "drag-handle";
    handle.textContent = "≡";
    li.append(handle);

    const span = document.createElement("span");
    span.className   = "account-name";
    span.textContent = hf? "•".repeat(name.length): name;

    const eyeBtn = document.createElement("button");
    eyeBtn.textContent = hf? "𓂋":"👁";
    eyeBtn.onclick     = () => toggleVisibility(li, span, eyeBtn);

    const editBtn = document.createElement("button");
    editBtn.textContent = "🖊";
    editBtn.onclick     = () => startEdit(name);

    const swBtn = document.createElement("button");
    swBtn.textContent = "Switch";
    swBtn.onclick     = () => {

      chrome.runtime.sendMessage({ action: "switch-account", name });
    };

    const dlBtn = document.createElement("button");
    dlBtn.textContent = "Delete";
    dlBtn.onclick     = () => deleteAccount(name);

    li.append(span, eyeBtn, editBtn, swBtn, dlBtn);

    li.addEventListener("dragstart", e => {
      e.dataTransfer.setData("text/plain", name);
      e.dropEffect = "move";
    });
    li.addEventListener("dragover", e => { e.preventDefault(); li.classList.add("drag-over"); });
    li.addEventListener("dragleave", () => li.classList.remove("drag-over"));
    li.addEventListener("drop", async e => {
      e.preventDefault(); li.classList.remove("drag-over");
      const from = e.dataTransfer.getData("text/plain");
      if (from && from!==name) {
        const idxFrom = order.indexOf(from);
        const idxTo   = order.indexOf(name);
        order.splice(idxFrom,1);
        order.splice(idxTo,0,from);
        await chrome.storage.local.set({ order });
        loadAccounts();
      }
    });

    list.append(li);
  }
}
