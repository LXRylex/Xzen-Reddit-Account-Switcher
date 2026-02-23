// reload.js — runs on reddit.com pages
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area !== "local" || !changes.lastSwitched) return;
  const { reloadAllTabs = true } = await chrome.storage.local.get("reloadAllTabs");
  if (reloadAllTabs || document.visibilityState === "visible") {
    window.location.reload();
  }
});
