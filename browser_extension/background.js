const DEVELOPMENT = chrome.runtime.getManifest().version_name === "development";
const BRIDGE = `http://127.0.0.1:${DEVELOPMENT ? 18765 : 8765}`;
async function clearLegacyMute(tab) {
  if (
    tab.mutedInfo?.muted &&
    tab.mutedInfo.reason === "extension" &&
    tab.mutedInfo.extensionId === chrome.runtime.id
  ) {
    await chrome.tabs.update(tab.id, {muted: false}).catch(() => {});
  }
}

chrome.tabs.query({}).then((tabs) => Promise.all(tabs.map(clearLegacyMute))).catch(() => {});

function sourceUrl(url) {
  try {
    const parsed = new URL(url);
    return parsed.protocol === "chrome-extension:"
      ? parsed.searchParams.get("sourceUrl") || url
      : url;
  } catch (_) {
    return url;
  }
}

async function publishTab(tabOrId, pageMediaPlaying = false) {
  const tab = typeof tabOrId === "number"
    ? await chrome.tabs.get(tabOrId).catch(() => null)
    : tabOrId;
  if (tab?.incognito) {
    await fetch(`${BRIDGE}/active`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({generic: true, audible: !!tab.audible})
    }).catch(() => {});
    await clearLegacyMute(tab);
    await chrome.tabs.sendMessage(tab.id, {
      type: "usage-guard-limit-state",
      state: null
    }).catch(() => {});
    return;
  }
  if (!tab || !tab.url) return;
  const url = sourceUrl(tab.url);
  if (!/^https?:\/\//.test(url)) return;
  try {
    const response = await fetch(`${BRIDGE}/active`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({
        url,
        title: tab.title || "",
        audible: !!tab.audible || !!pageMediaPlaying
      })
    });
    const payload = await response.json();
    await clearLegacyMute(tab);
    await chrome.tabs.sendMessage(tab.id, {
      type: "usage-guard-limit-state",
      state: payload.limit || null
    }).catch(() => {});
  } catch (_) {
    // Usage Guard may not be running yet; the next browser event retries.
  }
}

async function publishActiveTab(windowId = chrome.windows.WINDOW_ID_NONE) {
  const query = {active: true};
  if (windowId !== chrome.windows.WINDOW_ID_NONE) {
    query.windowId = windowId;
  } else {
    query.lastFocusedWindow = true;
  }
  const [tab] = await chrome.tabs.query(query);
  await publishTab(tab);
}

async function publishOpenTabs() {
  const tabs = await chrome.tabs.query({});
  const inventory = tabs.filter((tab) => !tab.incognito).map((tab) => ({
    url: sourceUrl(tab.url || ""),
    title: tab.title || "",
    audible: !!tab.audible
  })).filter((tab) => /^https?:\/\//.test(tab.url));
  await fetch(`${BRIDGE}/tabs`, {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({tabs: inventory})
  }).catch(() => {});
}

chrome.tabs.onActivated.addListener(({tabId}) => { publishTab(tabId); publishOpenTabs(); });
chrome.tabs.onUpdated.addListener((_tabId, _changeInfo, tab) => {
  if (tab.active) publishTab(tab);
  publishOpenTabs();
});
chrome.tabs.onCreated.addListener(() => publishOpenTabs());
chrome.tabs.onRemoved.addListener(() => publishOpenTabs());
chrome.tabs.onReplaced.addListener(() => publishOpenTabs());
chrome.windows.onFocusChanged.addListener((windowId) => publishActiveTab(windowId));
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "usage-guard-active-tab") {
    if (sender.tab?.active) publishTab(sender.tab, !!message.playing);
    return;
  }
  if (message.type === "usage-guard-grant-extension") {
    fetch(`${BRIDGE}/extension`, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({target_key: message.targetKey})
    }).then((response) => {
      sendResponse({accepted: response.ok});
      setTimeout(() => {
        if (sender.tab?.id) publishTab(sender.tab.id);
      }, 1100);
    }).catch(() => sendResponse({accepted: false}));
    return true;
  }
});
chrome.alarms.create("usage-guard-heartbeat", {periodInMinutes: 0.5});
chrome.alarms.onAlarm.addListener(() => { publishActiveTab(); publishOpenTabs(); });
publishActiveTab();
publishOpenTabs();
