const ENDPOINT = "http://127.0.0.1:8765/active";

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

async function publishActiveTab() {
  const [tab] = await chrome.tabs.query({active: true, lastFocusedWindow: true});
  if (!tab || !tab.url) return;
  const url = sourceUrl(tab.url);
  if (!/^https?:\/\//.test(url)) return;
  try {
    await fetch(ENDPOINT, {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url, title: tab.title || "", audible: !!tab.audible})
    });
  } catch (_) {
    // Usage Guard may not be running yet; the next browser event retries.
  }
}

chrome.tabs.onActivated.addListener(publishActiveTab);
chrome.tabs.onUpdated.addListener(publishActiveTab);
chrome.windows.onFocusChanged.addListener(publishActiveTab);
chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "usage-guard-active-tab") publishActiveTab();
});
chrome.alarms.create("usage-guard-heartbeat", {periodInMinutes: 0.5});
chrome.alarms.onAlarm.addListener(publishActiveTab);
publishActiveTab();
