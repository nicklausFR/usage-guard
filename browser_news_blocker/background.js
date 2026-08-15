const DEFAULT_DOMAINS = [
  "lemonde.fr", "lefigaro.fr", "liberation.fr", "franceinfo.fr",
  "bfmtv.com", "20minutes.fr", "mediapart.fr", "bbc.com", "cnn.com",
];
const notificationTimes = new Map();

function normalizeDomains(value) {
  return [...new Set(value
    .split(/\r?\n/)
    .map((domain) => domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.+$/, ""))
    .filter((domain) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain)))];
}

async function setCustomDomains(value) {
  const domains = normalizeDomains(value);
  await chrome.storage.sync.set({customDomains: domains.join("\n")});
  return domains;
}

function hostnameFor(url) {
  try {
    return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return "";
  }
}

function isNewsDomain(hostname, customDomains) {
  return [...DEFAULT_DOMAINS, ...customDomains].some(
    (domain) => hostname === domain || hostname.endsWith(`.${domain}`)
  );
}

async function notifyForNewsSite(tabId, url) {
  const hostname = hostnameFor(url);
  if (!hostname) return;
  const {customDomains = ""} = await chrome.storage.sync.get({customDomains: ""});
  if (!isNewsDomain(hostname, normalizeDomains(customDomains))) return;

  const now = Date.now();
  if (now - (notificationTimes.get(tabId) || 0) < 60_000) return;
  notificationTimes.set(tabId, now);
  chrome.notifications.create(`news-reminder-${tabId}`, {
    type: "basic",
    iconUrl: "icon.svg",
    title: "Usage Guard",
    message: `Attention à ne pas passer trop de temps sur ${hostname}.`,
    priority: 1,
  });
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.url) notifyForNewsSite(tabId, changeInfo.url);
});

chrome.tabs.onRemoved.addListener((tabId) => notificationTimes.delete(tabId));

chrome.runtime.onMessage.addListener((message, _sender, respond) => {
  if (message.type !== "save-custom-domains") return;
  setCustomDomains(message.domains)
    .then((domains) => respond({ok: true, domains}))
    .catch((error) => respond({ok: false, error: error.message}));
  return true;
});
