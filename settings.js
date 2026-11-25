/* settings.js - REPLACE ENTIRE FILE
 * - Portable backup v2 (works cross-browser / cross-device)
 * - Keeps: engine autosave, strength meter, preview diff, manage, wipe, export warning modal
 */

(async function(){
  const $  = (q,r=document)=>r.querySelector(q);
  const $$ = (q,r=document)=>Array.from(r.querySelectorAll(q));
  const enc = new TextEncoder();
  const dec = new TextDecoder();

  /* ===================== UI ===================== */
  const ui = {
    ver: $('#ver'), year: $('#year'),
    tablinks: $$('.tablink'), panels: $$('.panel'),

    // export warning modal
    exportModal: $('#exportModal'),
    exportAck: $('#exportAck'),
    exportWarningText: $('#exportWarningText'), exportAckText: $('#exportAckText'),
    exportCancel: $('#exportCancel'),
    exportContinue: $('#exportContinue'),

    // export
    expPass: $('#expPass'), expEye: $('#expEye'),
    passwordlessExport: $('#passwordlessExport'),
    expMeterBar: $('#expMeterBar'), expMeterText: $('#expMeterText'),
    btnExport: $('#btnExport'), expDot: $('#expDot'), expStatus: $('#expStatus'),

    // import
    impFile: $('#impFile'), impPass: $('#impPass'), impEye: $('#impEye'),
    impPassLabel: $('#impPassLabel'), impSecurityHint: $('#impSecurityHint'),
    btnPreview: $('#btnPreview'), btnImport: $('#btnImport'),
    impDot: $('#impDot'), impStatus: $('#impStatus'),
    replaceAll: $('#replaceAll'),

    // preview box
    previewBox: $('#previewBox'), pvAdd: $('#pvAdd'), pvUpd: $('#pvUpd'),
    pvSame: $('#pvSame'), pvDel: $('#pvDel'), previewList: $('#previewList'),

    // engine
    engineRadios: $$('input[name="engine"]'),
    kdfParams: $$('.kdf-params'),
    saveEngine: $('#saveEngine'), engDot: $('#engDot'), engStatus: $('#engStatus'),
    pbkIters256: $('#pbkIters256'), pbkIters512: $('#pbkIters512'),

    // manage
    search: $('#search'), acctList: $('#acctList'),

    // dev tools
    btnWipe: $('#btnWipe'), wipeDot: $('#wipeDot'), wipeStatus: $('#wipeStatus'),

    // popup behavior
    closeOnSwitch: $('#closeOnSwitch'),
    showLoggedOutProfile: $('#showLoggedOutProfile'),
    reloadActiveTabOnly: $('#reloadActiveTabOnly'),
    redirectHomeOnSwitch: $('#redirectHomeOnSwitch'),
    switchingDot: $('#switchingDot'),
    switchingStatus: $('#switchingStatus'),
  };

  try { ui.ver.textContent = 'v' + chrome.runtime.getManifest().version; } catch {}
  ui.year.textContent = String(new Date().getFullYear());

  // tabs
  ui.tablinks.forEach(b=>{
    b.addEventListener('click', ()=>{
      ui.tablinks.forEach(x=>x.classList.remove('active'));
      b.classList.add('active');
      const tab = b.dataset.tab;
      ui.panels.forEach(p=> p.id === `tab-${tab}` ? p.classList.add('active') : p.classList.remove('active'));
    });
  });

  // eyes
  const setupEye = (inp, eye)=> eye?.addEventListener('click', ()=>{ inp.type = inp.type==='password'?'text':'password'; });
  setupEye(ui.expPass, ui.expEye);
  setupEye(ui.impPass, ui.impEye);

  function syncPasswordlessUI(){
    const unsafe = !!ui.passwordlessExport?.checked;
    if (ui.expPass) ui.expPass.disabled = unsafe;
    if (ui.expEye) ui.expEye.disabled = unsafe;
    if (ui.expMeterBar) ui.expMeterBar.className = 'meter-bar';
    if (ui.expMeterText && unsafe) ui.expMeterText.textContent = 'Strength: not applicable';
    else if (ui.expMeterText) applyMeter(ui.expPass, ui.expMeterBar, ui.expMeterText);
  }
  ui.passwordlessExport?.addEventListener('change', syncPasswordlessUI);

  // status helper
  function setStatus(dot, txt, state, msg){
    if (!dot || !txt) return;
    dot.classList.remove('dot-idle','dot-ok','dot-fail');
    dot.classList.add(state==='ok'?'dot-ok':state==='fail'?'dot-fail':'dot-idle');
    txt.textContent = msg || (state==='ok'?'Saved':state==='fail'?'Error':'Idle');
  }

  /* ===================== Storage helpers ===================== */
  async function getState(keys){
    const def = {
      schemaVersion:2,
      profiles:{},
      order:[],
      hiddenStates:{},
      backupEngine:null,
      closeOnSwitch:false,
      showLoggedOutProfile:false,
      reloadActiveTabOnly:false,
      redirectHomeOnSwitch:false
    };
    const got = await chrome.storage.local.get(keys || Object.keys(def));
    return Object.assign(def, got);
  }
  async function setState(patch){ await chrome.storage.local.set(patch); }

  /* ===================== Device-key crypto (rawKey) ===================== */
  let deviceKey = null;

  // Keep each Function call well below V8's argument limit. Backups can easily
  // exceed that limit once several accounts/cookies are included.
  const B64_CHUNK_SIZE = 0x8000;
  const b64u8 = (u8)=>{
    let binary = '';
    for (let i = 0; i < u8.length; i += B64_CHUNK_SIZE) {
      binary += String.fromCharCode(...u8.subarray(i, i + B64_CHUNK_SIZE));
    }
    return btoa(binary);
  };
  const u8b64 = (s)=>{
    const binary = atob(s);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  };

  async function initDeviceCrypto(){
    let { rawKey } = await chrome.storage.local.get("rawKey");
    if (!rawKey) {
      const raw = crypto.getRandomValues(new Uint8Array(32));
      rawKey = b64u8(raw);
      await chrome.storage.local.set({ rawKey });
    }
    deviceKey = await crypto.subtle.importKey(
      "raw",
      u8b64(rawKey),
      { name: "AES-GCM" },
      false,
      ["encrypt","decrypt"]
    );
  }

  async function deviceEncryptBytes(bytes){
    if (!deviceKey) await initDeviceCrypto();
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({ name:"AES-GCM", iv }, deviceKey, bytes);
    const buf = new Uint8Array(iv.byteLength + ct.byteLength);
    buf.set(iv,0); buf.set(new Uint8Array(ct), iv.byteLength);
    return b64u8(buf);
  }

  async function deviceDecryptBytes(b64){
    if (!deviceKey) await initDeviceCrypto();
    const raw = u8b64(b64);
    const iv  = raw.slice(0,12), ct = raw.slice(12);
    const pt  = await crypto.subtle.decrypt({ name:"AES-GCM", iv }, deviceKey, ct);
    return new Uint8Array(pt);
  }

  async function deviceEncryptJSON(obj){
    return deviceEncryptBytes(enc.encode(JSON.stringify(obj)));
  }
  async function deviceDecryptJSON(b64){
    const bytes = await deviceDecryptBytes(b64);
    return JSON.parse(dec.decode(bytes));
  }

  await initDeviceCrypto();

  /* ===================== Password meter (export only) ===================== */
  function scorePass(s){
    if (!s) return {cls:'', txt:'Strength: -'};
    let score = 0;
    if (s.length >= 8) score++;
    if (s.length >= 12) score++;
    if (/[a-z]/.test(s) && /[A-Z]/.test(s)) score++;
    if (/\d/.test(s)) score++;
    if (/[^a-zA-Z0-9]/.test(s)) score++;
    if (score >= 4) return {cls:'meter-strong', txt:'Strength: Strong'};
    if (score >= 2) return {cls:'meter-ok', txt:'Strength: Okay'};
    return {cls:'meter-weak', txt:'Strength: Weak'};
  }

  function applyMeter(inp, bar, label){
    if (!inp || !bar || !label) return;
    const s = scorePass(inp.value);
    bar.classList.remove('meter-weak','meter-ok','meter-strong');
    if (s.cls) bar.classList.add(s.cls);
    label.textContent = s.txt;
  }

  ui.expPass?.addEventListener('input', ()=>applyMeter(ui.expPass, ui.expMeterBar, ui.expMeterText));
  applyMeter(ui.expPass, ui.expMeterBar, ui.expMeterText);

  /* ===================== Engine UI ===================== */
  function applyParamsVisibility(){
    const sel = $('input[name="engine"]:checked');
    const val = sel ? sel.value : 'aes-gcm';
    ui.kdfParams.forEach(p=>{
      const match = p.getAttribute('data-for') === val;
      p.classList.toggle('active', match);
    });
  }

  function readCurrentEngineFromUI(){
    const sel = $('input[name="engine"]:checked');
    const val = sel ? sel.value : 'aes-gcm';
    let kdf = null;

    if (val === 'pbkdf2-sha256'){
      kdf = { name:'pbkdf2-sha256', params:{ iterations:Number(ui.pbkIters256?.value||250000) } };
    } else if (val === 'pbkdf2-sha512'){
      kdf = { name:'pbkdf2-sha512', params:{ iterations:Number(ui.pbkIters512?.value||220000) } };
    } else {
      kdf = null;
    }

    return { cipher:'aes-gcm', kdf };
  }

  async function saveEngineAuto(){
    try{
      const engine = readCurrentEngineFromUI();
      await setState({ backupEngine: engine });
      setStatus(ui.engDot, ui.engStatus, 'ok', 'Saved');
    }catch(e){
      setStatus(ui.engDot, ui.engStatus, 'fail', e?.message || 'Save failed');
    }
    setTimeout(()=> setStatus(ui.engDot, ui.engStatus, 'idle','Idle'), 1200);
  }

  async function loadEngineToUI(){
    const st = await getState();
    let val = 'aes-gcm';
    const eng = st.backupEngine;

    // Only accept known KDF names. Unknown/old values fall back to AES.
    if (eng && eng.kdf && typeof eng.kdf.name === 'string'){
      if (eng.kdf.name === 'pbkdf2-sha256'){
        val = 'pbkdf2-sha256';
        if (eng.kdf.params?.iterations && ui.pbkIters256)
          ui.pbkIters256.value = eng.kdf.params.iterations;
      } else if (eng.kdf.name === 'pbkdf2-sha512'){
        val = 'pbkdf2-sha512';
        if (eng.kdf.params?.iterations && ui.pbkIters512)
          ui.pbkIters512.value = eng.kdf.params.iterations;
      } else {
        val = 'aes-gcm';
      }
    } else {
      await setState({ backupEngine: { cipher:'aes-gcm', kdf:null } });
    }

    ui.engineRadios.forEach(r=> r.checked = (r.value === val));
    applyParamsVisibility();
  }

  ui.engineRadios.forEach(r=>{
    r.addEventListener('change', ()=>{ applyParamsVisibility(); saveEngineAuto(); });
  });
  [ui.pbkIters256, ui.pbkIters512]
    .filter(Boolean)
    .forEach(inp=> inp.addEventListener('change', saveEngineAuto));
  $('#saveEngine')?.addEventListener('click', saveEngineAuto);
  await loadEngineToUI();

  /* ===================== Backup crypto (password) ===================== */
  function rnd(n){ const b=new Uint8Array(n); crypto.getRandomValues(b); return b; }
  const b64 = (u8) => b64u8(u8);
  const b64d = (s)  => u8b64(s);

  async function pbkdf2(bytes, salt, iters, hash){
    const mat = await crypto.subtle.importKey('raw', bytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt, iterations: iters, hash }, mat, 256);
    return new Uint8Array(bits);
  }

  async function deriveKey(pass, kdfSpec){
    const pw = typeof pass==='string' ? enc.encode(pass) : pass;
    const salt = rnd(16);

    if (!kdfSpec || !kdfSpec.name || kdfSpec.name === 'pbkdf2-sha256'){
      const it = (kdfSpec?.params?.iterations) || 250000;
      const kb = await pbkdf2(pw, salt, it, 'SHA-256');
      return { keyBytes: kb, salt, kdf:{ name:'pbkdf2-sha256', params:{ iterations: it } } };
    }

    if (kdfSpec.name === 'pbkdf2-sha512'){
      const it = (kdfSpec?.params?.iterations) || 220000;
      const kb = await pbkdf2(pw, salt, it, 'SHA-512');
      return { keyBytes: kb, salt, kdf:{ name:'pbkdf2-sha512', params:{ iterations: it } } };
    }

    const it = 250000;
    const kb = await pbkdf2(pw, salt, it, 'SHA-256');
    return { keyBytes: kb, salt, kdf:{ name:'pbkdf2-sha256', params:{ iterations: it } } };
  }

  async function deriveKeyFromHeader(pass, header){
    const pw = typeof pass==='string' ? enc.encode(pass) : pass;
    const salt = b64d(header.salt);
    const kdf = header.kdf || { name:'pbkdf2-sha256', params:{ iterations:250000 } };

    if (kdf.name === 'pbkdf2-sha256')
      return pbkdf2(pw, salt, kdf.params.iterations, 'SHA-256');

    if (kdf.name === 'pbkdf2-sha512')
      return pbkdf2(pw, salt, kdf.params.iterations, 'SHA-512');

    throw new Error('Unknown KDF in backup');
  }

  async function aesEnc(keyBytes, plain){
    const iv = rnd(12);
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt']);
    const ct = await crypto.subtle.encrypt({ name:'AES-GCM', iv }, key, plain);
    return { iv, ct: new Uint8Array(ct) };
  }

  async function aesDec(keyBytes, iv, ct){
    const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name:'AES-GCM', iv }, key, ct);
    return new Uint8Array(pt);
  }

  /* ===================== Portable format helpers ===================== */
  function cookieKey(c){
    return `${c?.name||""}|${c?.domain||""}|${c?.path||"/"}`;
  }
  function cookieSig(cookies){
    const arr = Array.isArray(cookies) ? cookies : [];
    const norm = arr.map(c=>({
      name: c?.name || "",
      domain: c?.domain || "",
      path: c?.path || "/",
      value: c?.value || "",
      secure: !!c?.secure,
      httpOnly: !!c?.httpOnly,
      sameSite: c?.sameSite || "",
      expirationDate: c?.expirationDate || 0,
      session: !!c?.session
    }));
    norm.sort((a,b)=> cookieKey(a).localeCompare(cookieKey(b)));
    return JSON.stringify(norm);
  }

  async function buildPortableProfiles(profiles){
    const out = {};
    for (const [id, p] of Object.entries(profiles || {})){
      if (!p) continue;
      let cookies = [];
      if (typeof p.encCookies === "string" && p.encCookies){
        try { cookies = await deviceDecryptJSON(p.encCookies); }
        catch { cookies = []; }
      }
      out[id] = {
        name: p.name || "",
        cookies: Array.isArray(cookies) ? cookies : [],
        tags: Array.isArray(p.tags) ? p.tags : [],
        note: typeof p.note === "string" ? p.note : "",
        createdAt: p.createdAt || Date.now(),
        updatedAt: p.updatedAt || p.createdAt || Date.now(),
      };
    }
    return out;
  }

  async function rewrapImportedProfiles(inProfiles){
    const out = {};
    for (const [id, p] of Object.entries(inProfiles || {})){
      if (!p) continue;

      let cookies = null;

      // New portable backups: cookies[]
      if (Array.isArray(p.cookies)){
        cookies = p.cookies;
      }
      // Legacy backups (v1): encCookies (device-key encrypted on *exporter* browser)
      else if (typeof p.encCookies === "string" && p.encCookies){
        try {
          cookies = await deviceDecryptJSON(p.encCookies);
        } catch (e) {
          throw new Error(
            "This backup is an older format that was tied to the exporting browser/device. " +
            "Re-export the backup using the updated uSwitch (portable backup v2), then import again."
          );
        }
      } else {
        cookies = [];
      }

      out[id] = {
        name: p.name || "",
        encCookies: await deviceEncryptJSON(Array.isArray(cookies) ? cookies : []),
        tags: Array.isArray(p.tags) ? p.tags : [],
        note: typeof p.note === "string" ? p.note : "",
        createdAt: p.createdAt || Date.now(),
        updatedAt: Date.now(),
      };
    }
    return out;
  }

  /* ===================== Export ===================== */
  function startBrowserDownload(options){
    return new Promise((resolve, reject)=>{
      chrome.downloads.download(options, (downloadId)=>{
        const err = chrome.runtime.lastError;
        if (err) return reject(new Error(err.message));
        if (!Number.isInteger(downloadId)) return reject(new Error('The browser did not start the download'));
        resolve(downloadId);
      });
    });
  }

  function waitForBrowserDownload(downloadId){
    return new Promise((resolve, reject)=>{
      let settled = false;

      const finish = (error)=>{
        if (settled) return;
        settled = true;
        chrome.downloads.onChanged.removeListener(onChanged);
        if (error) reject(error);
        else resolve();
      };

      const failure = (code)=> new Error(
        code === 'USER_CANCELED' ? 'Save canceled' : `Save failed: ${code || 'DOWNLOAD_INTERRUPTED'}`
      );

      const inspect = (item)=>{
        if (!item) return;
        if (item.state === 'complete') finish();
        else if (item.state === 'interrupted') finish(failure(item.error));
      };

      const onChanged = (delta)=>{
        if (delta.id !== downloadId) return;
        if (delta.error?.current) return finish(failure(delta.error.current));
        if (delta.state?.current === 'complete') finish();
        else if (delta.state?.current === 'interrupted') finish(failure());
      };

      chrome.downloads.onChanged.addListener(onChanged);
      chrome.downloads.search({ id: downloadId }, (items)=>{
        const err = chrome.runtime.lastError;
        if (err) return finish(new Error(err.message));
        inspect(items?.[0]);
      });
    });
  }

  async function download(bytes, name){
    const blob = new Blob([bytes], { type:'application/octet-stream' });
    const url = URL.createObjectURL(blob);

    if (chrome?.downloads?.download) {
      try {
        const downloadId = await startBrowserDownload({ url, filename:name, saveAs:true });
        await waitForBrowserDownload(downloadId);
        return;
      } finally {
        URL.revokeObjectURL(url);
      }
    }

    const a = document.createElement('a');
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(()=>{ URL.revokeObjectURL(a.href); a.remove(); }, 60000);
  }

  async function exportBackup(){
    setStatus(ui.expDot, ui.expStatus, 'idle', 'Working…');
    let exported = false;
    try{
      const st = await getState();
      const passwordless = !!ui.passwordlessExport?.checked;
      const pass = ui.expPass.value.trim();
      if (!passwordless && !pass) throw new Error('Password required');

      const portableProfiles = await buildPortableProfiles(st.profiles);

      const data = {
        schemaVersion: 2,
        format: "portable-v2",
        profiles: portableProfiles,
        order: Array.isArray(st.order) && st.order.length ? st.order : Object.keys(portableProfiles),
        hiddenStates: st.hiddenStates || {},
        ts: Date.now()
      };

      let header, payload;
      if (passwordless){
        header = { magic:'USWITCH', ver:2, format:'portable-v2', cipher:'none', security:'unencrypted' };
        payload = b64(enc.encode(JSON.stringify(data)));
      } else {
        const kdfSpec = (st.backupEngine && st.backupEngine.kdf) ? st.backupEngine.kdf : null;
        const { keyBytes, salt, kdf } = await deriveKey(pass, kdfSpec);
        const { iv, ct } = await aesEnc(keyBytes, enc.encode(JSON.stringify(data)));
        header = { magic:'USWITCH', ver:2, format:'portable-v2', cipher:'aes-gcm', kdf, salt:b64(salt), iv:b64(iv) };
        payload = b64(ct);
      }
      const out = enc.encode(JSON.stringify({ header, data: payload }));

      const fname = `uSwitch-backup-${new Date().toISOString().slice(0,10)}.uSwitch`;
      await download(out, fname);

      setStatus(ui.expDot, ui.expStatus, 'ok', 'Exported');
      exported = true;
    }catch(e){
      console.error('Export failed', e);
      setStatus(ui.expDot, ui.expStatus, 'fail', e?.message || 'Export failed');
    }
    if (exported) setTimeout(()=> setStatus(ui.expDot, ui.expStatus, 'idle','Idle'), 1800);
  }

  // Export modal (custom)
  function openExportModal(){
    if (!ui.exportModal) return exportBackup();
    ui.exportModal.classList.remove('hidden');
    document.body.classList.add('modal-open');
    if (ui.exportAck) ui.exportAck.checked = false;
    if (ui.exportContinue) ui.exportContinue.disabled = true;
    const unsafe = !!ui.passwordlessExport?.checked;
    if (ui.exportWarningText) ui.exportWarningText.innerHTML = unsafe
      ? 'This passwordless backup contains your Reddit account data <b>without encryption</b>.<br><br>Anyone who obtains it may be able to access your saved accounts. Never share or publicly upload it. You accept all potential security risks and full responsibility for using and storing this file.<br><br><b>Anti-scam notice:</b> I will never contact you or request this file, your password, cookies, or account data for support. Anyone asking for them may be a scammer impersonating support.'
      : 'Your <code>.uSwitch</code> backup contains your saved account data.<br><br><b>Never share it.</b> Don’t upload it to Drive links, Discord, or public sites. If someone gets this file + your password, they can import your accounts.<br><br><b>Anti-scam notice:</b> I will never contact you or request this file, your password, cookies, or account data for support. Anyone asking for them may be a scammer impersonating support.';
    if (ui.exportAckText) ui.exportAckText.textContent = unsafe
      ? 'I understand the security risks and accept full responsibility.'
      : 'I understand. I will not share the backup file.';
    ui.exportCancel?.focus();
  }
  function closeExportModal(){
    if (!ui.exportModal) return;
    ui.exportModal.classList.add('hidden');
    document.body.classList.remove('modal-open');
  }

  ui.btnExport?.addEventListener('click', (e)=>{
    e.preventDefault();
    openExportModal();
  });

  ui.exportAck?.addEventListener('change', ()=>{
    if (ui.exportContinue) ui.exportContinue.disabled = !ui.exportAck.checked;
  });

  ui.exportCancel?.addEventListener('click', closeExportModal);

  ui.exportModal?.addEventListener('click', (e)=>{
    const t = e.target;
    if (t && t.getAttribute && t.getAttribute('data-close') === '1') closeExportModal();
  });

  document.addEventListener('keydown', (e)=>{
    if (e.key === 'Escape' && ui.exportModal && !ui.exportModal.classList.contains('hidden')) {
      closeExportModal();
    }
  });

  ui.exportContinue?.addEventListener('click', async ()=>{
    if (!ui.exportAck?.checked) return;
    closeExportModal();
    await exportBackup();
  });

  /* ===================== Import & Preview ===================== */
  function readText(file){
    return new Promise((res, rej)=>{
      const fr = new FileReader();
      fr.onload = ()=>res(String(fr.result));
      fr.onerror = ()=>rej(new Error('Read failed'));
      fr.readAsText(file);
    });
  }

  ui.impFile?.addEventListener('change', async ()=>{
    let passwordless = false;
    try {
      const file = ui.impFile.files?.[0];
      if (file) passwordless = JSON.parse(await readText(file))?.header?.cipher === 'none';
    } catch {}
    if (ui.impPass) {
      ui.impPass.disabled = passwordless;
      if (passwordless) ui.impPass.value = '';
    }
    if (ui.impEye) ui.impEye.disabled = passwordless;
    if (ui.impPassLabel) ui.impPassLabel.textContent = passwordless ? 'Password (not required)' : 'Password';
    if (ui.impSecurityHint) ui.impSecurityHint.textContent = passwordless
      ? 'Passwordless backup detected. This file is unencrypted; no password is required.'
      : 'Encrypted backups require their password.';
  });

  async function decryptSelectedBackup(){
    const f = ui.impFile.files?.[0];
    if (!f) throw new Error('No file selected');

    const text = await readText(f);

    let parsed;
    try { parsed = JSON.parse(text); }
    catch { throw new Error('File is not a valid uSwitch backup'); }

    const h = parsed.header;
    if (!h || h.magic!=='USWITCH' || !['aes-gcm','none'].includes(h.cipher)){
      throw new Error('File is not a supported uSwitch backup');
    }

    if (h.cipher === 'none'){
      let obj;
      try { obj = JSON.parse(dec.decode(b64d(parsed.data))); }
      catch { throw new Error('Unencrypted backup contents are corrupted'); }
      return obj;
    }

    const pass = ui.impPass.value.trim();
    if (!pass) throw new Error('Password required');

    const keyBytes = await deriveKeyFromHeader(pass, h);

    let pt;
    try {
      pt = await aesDec(keyBytes, b64d(h.iv), b64d(parsed.data));
    } catch {
      throw new Error('Wrong password or corrupted backup');
    }

    let obj;
    try { obj = JSON.parse(dec.decode(pt)); }
    catch { throw new Error('Backup contents are corrupted'); }

    obj._header = h;
    return obj;
  }

  async function diffProfiles(existing, incoming, replaceAll){
    const e = existing || {};
    const i = incoming || {};
    const toAdd=[], toUpd=[], same=[], toDel=[];

    const eSig = new Map();
    for (const [id, prof] of Object.entries(e)){
      if (!prof) continue;
      try {
        const cookies = await deviceDecryptJSON(prof.encCookies);
        eSig.set(id, cookieSig(cookies) + "|" + String(prof.name||""));
      } catch {
        eSig.set(id, "__ERR__|" + String(prof.name||""));
      }
    }

    for (const [id, prof] of Object.entries(i)){
      if (!e[id]) { toAdd.push({ id, prof }); continue; }

      let inCookiesSig = "";
      try {
        if (Array.isArray(prof.cookies)) inCookiesSig = cookieSig(prof.cookies);
        else if (prof.encCookies) {
          const cookies = await deviceDecryptJSON(prof.encCookies);
          inCookiesSig = cookieSig(cookies);
        } else inCookiesSig = cookieSig([]);
      } catch {
        inCookiesSig = "__ERR__";
      }

      const nowSig = inCookiesSig + "|" + String(prof.name||"");
      const oldSig = eSig.get(id) || "";
      const changed = nowSig !== oldSig;

      (changed ? toUpd : same).push({ id, prof });
    }

    if (replaceAll){
      for (const id of Object.keys(e)){
        if (!i[id]) toDel.push({ id, prof: e[id] });
      }
    }

    return { toAdd, toUpd, same, toDel };
  }

  function renderPreview(diff){
    ui.previewBox.classList.remove('hidden');
    ui.pvAdd.textContent  = String(diff.toAdd.length);
    ui.pvUpd.textContent  = String(diff.toUpd.length);
    ui.pvSame.textContent = String(diff.same.length);
    ui.pvDel.textContent  = String(diff.toDel.length);

    const items = [];
    const push = (arr, cls, label) => {
      arr.slice(0, 10).forEach(x=>{
        const li = document.createElement('li');
        li.className = 'preview-item';
        const b = document.createElement('span'); b.className = 'badge-mini ' + cls; b.textContent = label;
        const t = document.createElement('span'); t.textContent = x.prof?.name || '(unnamed)';
        li.append(b,t); items.push(li);
      });
    };
    push(diff.toAdd,'add','NEW');
    push(diff.toUpd,'upd','UPDATE');
    push(diff.same,'same','SAME');
    push(diff.toDel,'del','REMOVE');

    ui.previewList.innerHTML = '';
    items.forEach(n=> ui.previewList.appendChild(n));

    const sub = ui.previewBox.querySelector('.preview-head .small');
    if (sub) sub.textContent = 'Showing up to 10 per category';
  }

  async function previewImport(){
    setStatus(ui.impDot, ui.impStatus, 'idle', 'Decrypting…');
    try{
      const pack = await decryptSelectedBackup();
      const st = await getState(['profiles']);
      const diff = await diffProfiles(st.profiles, pack.profiles, !!ui.replaceAll.checked);
      renderPreview(diff);
      setStatus(ui.impDot, ui.impStatus, 'ok', 'Preview ready');
    }catch(e){
      console.error('Preview failed', e);
      setStatus(ui.impDot, ui.impStatus, 'fail', e?.message || 'Preview failed');
    }
    setTimeout(()=> setStatus(ui.impDot, ui.impStatus, 'idle','Idle'), 1800);
  }
  ui.btnPreview?.addEventListener('click', previewImport);

  async function importBackup(){
    setStatus(ui.impDot, ui.impStatus, 'idle', 'Working…');
    try{
      const pack = await decryptSelectedBackup();
      const replace = !!ui.replaceAll.checked;

      const importedProfiles = await rewrapImportedProfiles(pack.profiles || {});
      const importedOrder = Array.isArray(pack.order) ? pack.order.filter(id=> importedProfiles[id]) : Object.keys(importedProfiles);
      const importedHidden = pack.hiddenStates || {};

      const st = await getState();

      if (replace){
        await setState({
          schemaVersion: 2,
          profiles: importedProfiles,
          order: importedOrder,
          hiddenStates: importedHidden
        });
      } else {
        const profiles = Object.assign({}, st.profiles);
        const order = Array.from(st.order||[]);
        const hidden = Object.assign({}, st.hiddenStates);

        for (const [id, prof] of Object.entries(importedProfiles)){
          profiles[id] = prof;
          if (!order.includes(id)) order.push(id);
        }
        Object.assign(hidden, importedHidden);

        await setState({ schemaVersion: 2, profiles, order, hiddenStates: hidden });
      }

      setStatus(ui.impDot, ui.impStatus, 'ok', 'Imported');
      await renderManage();
    }catch(e){
      console.error('Import failed', e);
      setStatus(ui.impDot, ui.impStatus, 'fail', e?.message || 'Import failed');
    }
    setTimeout(()=> setStatus(ui.impDot, ui.impStatus, 'idle','Idle'), 1800);
  }
  ui.btnImport?.addEventListener('click', importBackup);

  /* ===================== Manage ===================== */
  function matches(entry, q){
    if (!q) return true;
    q = q.trim().toLowerCase();
    if (q.startsWith('#')){
      const t = q.slice(1);
      return (entry.tags||[]).some(s=> String(s).toLowerCase().includes(t));
    }
    return (
      String(entry.name||'').toLowerCase().includes(q) ||
      String(entry.note||'').toLowerCase().includes(q) ||
      (entry.tags||[]).some(s=> String(s).toLowerCase().includes(q))
    );
  }

  function tagPill(text, onEdit, onDel){
    const s = document.createElement('span'); s.className='tag';
    const t = document.createElement('span'); t.className='tag-text'; t.textContent = `#${text}`;
    const a = document.createElement('span'); a.className='tag-actions';
    const e = document.createElement('button'); e.className='icon-btn'; e.title='Edit'; e.textContent='🖊';
    const x = document.createElement('button'); x.className='icon-btn'; x.title='Delete'; x.textContent='×';
    e.onclick = (ev)=>{ ev.stopPropagation(); const nu = prompt('Rename tag', text); if (nu && nu.trim()) onEdit(nu.trim()); };
    x.onclick = (ev)=>{ ev.stopPropagation(); onDel(); };
    a.append(e,x); s.append(t,a); return s;
  }

  async function renderManage(){
    const st = await getState(['profiles','order','hiddenStates']);
    const q = (ui.search.value||'').toLowerCase();
    ui.acctList.innerHTML = '';

    for (const id of st.order){
      const p = st.profiles[id]; if (!p) continue;
      p.tags = Array.isArray(p.tags)? p.tags : [];
      p.note = typeof p.note==='string' ? p.note : '';

      if (!matches({ name:p.name, note:p.note, tags:p.tags }, q)) continue;

      const li = document.createElement('li'); li.className='acct-item';

      const head = document.createElement('div'); head.className = 'acct-head';
      const nm = document.createElement('div');
      nm.className='acct-name';
      nm.textContent = p.name || '(unnamed)';

      const noteLine = document.createElement('div');
      noteLine.className = 'acct-note ' + (p.note ? '' : 'is-empty');
      noteLine.textContent = p.note ? p.note : 'No note';

      head.append(nm, noteLine);
      li.append(head);

      const tagWrap = document.createElement('div'); tagWrap.className='tags';
      const renderTags = async ()=>{
        tagWrap.innerHTML = '';
        (p.tags||[]).forEach((tg,i)=>{
          tagWrap.appendChild(tagPill(tg, async (nu)=>{
            p.tags[i]=nu;
            const st2=await getState(['profiles']);
            st2.profiles[id].tags=[...p.tags];
            await setState({profiles:st2.profiles});
            renderTags();
          }, async ()=>{
            p.tags.splice(i,1);
            const st2=await getState(['profiles']);
            st2.profiles[id].tags=[...p.tags];
            await setState({profiles:st2.profiles});
            renderTags();
          }));
        });

        const add=document.createElement('input');
        add.className='tag-input';
        add.placeholder='Add tag…';
        add.addEventListener('keydown', async e=>{
          if (e.key==='Enter'){
            const v=add.value.trim();
            if (v){
              p.tags.push(v);
              const st2=await getState(['profiles']);
              st2.profiles[id].tags=[...p.tags];
              await setState({profiles:st2.profiles});
              add.value='';
              renderTags();
            }
          }
        });
        tagWrap.append(add);
      };
      renderTags();
      li.append(tagWrap);

      const fill=document.createElement('div'); fill.className='rowfill';
      li.append(fill);

      const act=document.createElement('div'); act.className='actions-row';

      const ren=document.createElement('button');
      ren.className='action';
      ren.textContent='Rename';
      ren.onclick = async ()=>{
        const nu=prompt('New name', p.name||'');
        if(nu && nu.trim()){
          const st2=await getState(['profiles']);
          st2.profiles[id].name=nu.trim();
          await setState({profiles:st2.profiles});
          renderManage();
        }
      };

      const note=document.createElement('button');
      note.className='action';
      note.textContent = p.note ? 'Edit note' : 'Add note';
      note.title = p.note || 'No note';
      note.onclick = async ()=>{
        const nu=prompt('Note for this account', p.note||'');
        if(nu!=null){
          const st2=await getState(['profiles']);
          st2.profiles[id].note=String(nu);
          await setState({profiles:st2.profiles});
          renderManage();
        }
      };

      const del=document.createElement('button');
      del.className='action';
      del.textContent='Delete';
      del.onclick = async ()=>{
        if(!confirm(`Delete “${p.name}”? This cannot be undone.`)) return;
        const st2=await getState(['profiles','order','hiddenStates']);
        delete st2.profiles[id];
        delete st2.hiddenStates[id];
        const i=st2.order.indexOf(id); if(i>-1) st2.order.splice(i,1);
        await setState({profiles:st2.profiles, hiddenStates:st2.hiddenStates, order:st2.order});
        renderManage();
      };

      act.append(ren,note,del);
      li.append(act);

      li.title = p.note || '';
      ui.acctList.append(li);
    }
  }

  ui.search?.addEventListener('input', renderManage);
  await renderManage();

  /* ===================== Popup setting: close after switch ===================== */
  async function loadCloseSetting(){
    const st = await getState(['closeOnSwitch']);
    if (ui.closeOnSwitch) ui.closeOnSwitch.checked = !!st.closeOnSwitch;
  }

  async function saveCloseSetting(){
    try{
      await setState({ closeOnSwitch: !!ui.closeOnSwitch?.checked });
      setStatus(ui.switchingDot, ui.switchingStatus, 'ok', 'Saved');
    }catch(e){
      setStatus(ui.switchingDot, ui.switchingStatus, 'fail', e?.message || 'Save failed');
    }
    setTimeout(()=> setStatus(ui.switchingDot, ui.switchingStatus, 'idle','Idle'), 1200);
  }

  ui.closeOnSwitch?.addEventListener('change', saveCloseSetting);
  await loadCloseSetting();

  async function loadLoggedOutProfileSetting(){
    const st = await getState(['showLoggedOutProfile']);
    if (ui.showLoggedOutProfile) ui.showLoggedOutProfile.checked = !!st.showLoggedOutProfile;
  }

  async function saveLoggedOutProfileSetting(){
    try{
      await setState({ showLoggedOutProfile: !!ui.showLoggedOutProfile?.checked });
      setStatus(ui.switchingDot, ui.switchingStatus, 'ok', 'Saved');
    }catch(e){
      setStatus(ui.switchingDot, ui.switchingStatus, 'fail', e?.message || 'Save failed');
    }
    setTimeout(()=> setStatus(ui.switchingDot, ui.switchingStatus, 'idle','Idle'), 1200);
  }

  ui.showLoggedOutProfile?.addEventListener('change', saveLoggedOutProfileSetting);
  await loadLoggedOutProfileSetting();

  /* ===================== Reload setting: active Reddit tab only ===================== */
  async function loadReloadSetting(){
    const st = await getState(['reloadActiveTabOnly']);
    if (ui.reloadActiveTabOnly) ui.reloadActiveTabOnly.checked = !!st.reloadActiveTabOnly;
  }

  async function saveReloadSetting(){
    try{
      await setState({ reloadActiveTabOnly: !!ui.reloadActiveTabOnly?.checked });
      setStatus(ui.switchingDot, ui.switchingStatus, 'ok', 'Saved');
    }catch(e){
      setStatus(ui.switchingDot, ui.switchingStatus, 'fail', e?.message || 'Save failed');
    }
    setTimeout(()=> setStatus(ui.switchingDot, ui.switchingStatus, 'idle','Idle'), 1200);
  }

  ui.reloadActiveTabOnly?.addEventListener('change', saveReloadSetting);
  await loadReloadSetting();

  /* ===================== Redirect to Reddit home after switching ===================== */
  async function loadRedirectSetting(){
    const st = await getState(['redirectHomeOnSwitch']);
    if (ui.redirectHomeOnSwitch) ui.redirectHomeOnSwitch.checked = !!st.redirectHomeOnSwitch;
  }

  async function saveRedirectSetting(){
    try{
      await setState({ redirectHomeOnSwitch: !!ui.redirectHomeOnSwitch?.checked });
      setStatus(ui.switchingDot, ui.switchingStatus, 'ok', 'Saved');
    }catch(e){
      setStatus(ui.switchingDot, ui.switchingStatus, 'fail', e?.message || 'Save failed');
    }
    setTimeout(()=> setStatus(ui.switchingDot, ui.switchingStatus, 'idle','Idle'), 1200);
  }

  ui.redirectHomeOnSwitch?.addEventListener('change', saveRedirectSetting);
  await loadRedirectSetting();

  /* ===================== Developer Tools: wipe all ===================== */
  async function wipeAll(){
    if (!confirm('This will wipe ALL uSwitch data & Reddit cookies on this browser. Continue?')) return;
    if (!confirm('Are you absolutely sure? This cannot be undone.')) return;
    setStatus(ui.wipeDot, ui.wipeStatus, 'idle', 'Wiping…');
    try{
      await chrome.storage.local.clear();

      const domains = ['.reddit.com','reddit.com'];
      const cookies = (await Promise.all(domains.map(d=> chrome.cookies.getAll({ domain:d })))).flat();
      const map = new Map();
      cookies.forEach(c => map.set(`${c.name}|${c.domain}|${c.path||'/'}`, c));
      const all = [...map.values()];
      const urlFor = (c)=> (c.secure?'https://':'http://') + (c.domain||'reddit.com').replace(/^\./,'') + (c.path||'/');
      await Promise.allSettled(all.map(c=> chrome.cookies.remove({ url:urlFor(c), name:c.name })));

      setStatus(ui.wipeDot, ui.wipeStatus, 'ok', 'Wiped');
    }catch(e){
      console.error('Wipe failed', e);
      setStatus(ui.wipeDot, ui.wipeStatus, 'fail', e?.message || 'Wipe failed');
    }
    setTimeout(()=> setStatus(ui.wipeDot, ui.wipeStatus, 'idle','Idle'), 1800);
  }
  ui.btnWipe?.addEventListener('click', wipeAll);

})();
