(() => {
  const DEFAULT_DOMAINS = [
    "lemonde.fr", "lefigaro.fr", "liberation.fr", "franceinfo.fr",
    "bfmtv.com", "20minutes.fr", "mediapart.fr", "bbc.com", "cnn.com",
  ];

  function normalizeDomains(value) {
    return value
      .split(/\r?\n/)
      .map((domain) => domain.trim().toLowerCase().replace(/^https?:\/\//, "").replace(/^www\./, "").replace(/\/.+$/, ""))
      .filter((domain) => /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(domain));
  }

  function isNewsDomain(domain, watchedDomains) {
    return watchedDomains.some(
      (watched) => domain === watched || domain.endsWith(`.${watched}`)
    );
  }

  chrome.storage.sync.get({customDomains: ""}, ({customDomains}) => {
    const hostname = location.hostname.toLowerCase().replace(/^www\./, "");
    if (!isNewsDomain(hostname, [...DEFAULT_DOMAINS, ...normalizeDomains(customDomains)])) {
      return;
    }

    // One allowance is shared by every monitored news domain, rather than
    // resetting when the user switches from Mediapart to BBC, for example.
    const stateKey = "news-reminder:actualites";
    const legacyStateKey = `news-reminder:${hostname}`;
    chrome.storage.local.get({[stateKey]: null, [legacyStateKey]: null}, (stored) => {
    const savedState = stored[stateKey] || stored[legacyStateKey];
    let periodSeconds = savedState?.periodSeconds || 2 * 60;
    let remainingSeconds = Number.isInteger(savedState?.remainingSeconds)
      ? savedState.remainingSeconds
      : periodSeconds;
    let extensionUsed = Boolean(savedState?.extensionUsed);
    const reminder = document.createElement("aside");
    const text = document.createElement("span");
    const countdown = document.createElement("strong");
    const progress = document.createElement("div");
    const fill = document.createElement("div");
    const extensionButton = document.createElement("button");
    const blockOverlay = document.createElement("div");
    text.textContent = "Usage Guard — Be mindful of how much time you spend on this website.";
    reminder.setAttribute("role", "status");
    reminder.style.cssText = [
      "position:fixed", "z-index:2147483647", "top:0", "left:0", "right:0",
      "box-sizing:border-box", "height:58px", "padding:10px 24px 8px",
      "background:#4a171b", "border-bottom:1px solid #ff6b6b", "color:#fff",
      "font:600 14px system-ui,sans-serif", "box-shadow:0 3px 12px #0007",
    ].join(";");
    countdown.style.cssText = "float:right; color:#ffb3b3; font-variant-numeric:tabular-nums;";
    progress.style.cssText = "height:5px; margin-top:9px; overflow:hidden; border-radius:99px; background:#7a3035;";
    fill.style.cssText = "height:100%; width:0%; background:#ff5a5f; transition:width .5s linear;";
    extensionButton.textContent = "Get a one-time 1 min extension";
    extensionButton.style.cssText = [
      "display:none", "float:right", "margin:-5px 0 0 14px", "padding:5px 10px",
      "border:1px solid #ffb3b3", "border-radius:5px", "background:#7a2026",
      "color:#fff", "font:600 12px system-ui,sans-serif", "cursor:pointer",
    ].join(";");
    blockOverlay.style.cssText = [
      "display:none", "position:fixed", "z-index:2147483646", "top:58px",
      "right:0", "bottom:0", "left:0", "background:#220b0dcc",
      "backdrop-filter:blur(5px)", "cursor:not-allowed",
    ].join(";");
    progress.append(fill);
    reminder.append(text, extensionButton, countdown, progress);
    document.documentElement.append(blockOverlay, reminder);

    const saveState = () => chrome.storage.local.set({
      [stateKey]: {periodSeconds, remainingSeconds, extensionUsed},
    });
    let timer = null;
    const update = () => {
      const remaining = remainingSeconds;
      const elapsed = periodSeconds - remaining;
      const minutes = String(Math.floor(remaining / 60)).padStart(2, "0");
      const seconds = String(remaining % 60).padStart(2, "0");
      countdown.textContent = `${minutes}:${seconds}`;
      fill.style.width = `${(elapsed / periodSeconds) * 100}%`;
      if (remaining === 0) {
        text.textContent = "Usage Guard — Time is up. Take a break.";
        fill.style.background = "#ef5350";
        blockOverlay.style.display = "block";
        if (!extensionUsed) extensionButton.style.display = "inline-block";
        clearInterval(timer);
        saveState();
      }
    };
    const tick = () => {
      // A news page must not consume its allowance while it is hidden behind
      // another tab or while the browser window is minimized.
      if (document.visibilityState !== "visible" || remainingSeconds === 0) return;
      remainingSeconds -= 1;
      update();
      saveState();
    };
    extensionButton.addEventListener("click", () => {
      extensionUsed = true;
      periodSeconds = 60;
      remainingSeconds = periodSeconds;
      text.textContent = "Usage Guard — One-time extension in progress.";
      fill.style.background = "#ff5a5f";
      extensionButton.style.display = "none";
      blockOverlay.style.display = "none";
      clearInterval(timer);
      timer = setInterval(tick, 1000);
      update();
      saveState();
    });
    update();
    if (remainingSeconds > 0) timer = setInterval(tick, 1000);
    addEventListener("pagehide", saveState);
    });
  });
})();
