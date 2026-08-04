function notifyUsageGuard() {
  if (!document.hidden) {
    chrome.runtime.sendMessage({type: "usage-guard-active-tab"}).catch(() => {});
  }
}

document.addEventListener("visibilitychange", notifyUsageGuard);
window.addEventListener("focus", notifyUsageGuard);
setInterval(notifyUsageGuard, 2000);
notifyUsageGuard();
