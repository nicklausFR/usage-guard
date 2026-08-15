let limitUi = null;
let mediaBlockTimer = null;
let mediaToResume = new Set();
let resumeMediaAfterBlock = false;

function tr(key, substitutions) {
  return chrome.i18n.getMessage(key, substitutions) || key;
}

function pausePageMedia(capturePlaying = false) {
  document.querySelectorAll("video, audio").forEach((media) => {
    try {
      if (capturePlaying && !media.paused && !media.ended) {
        mediaToResume.add(media);
        resumeMediaAfterBlock = true;
      }
      media.pause();
    } catch (_) {}
  });
}

function setMediaBlocked(blocked) {
  if (blocked) {
    if (mediaBlockTimer === null) {
      mediaToResume = new Set();
      resumeMediaAfterBlock = false;
      pausePageMedia(true);
    } else {
      pausePageMedia();
    }
    if (mediaBlockTimer === null) mediaBlockTimer = setInterval(pausePageMedia, 250);
  } else if (mediaBlockTimer !== null) {
    clearInterval(mediaBlockTimer);
    mediaBlockTimer = null;
    if (resumeMediaAfterBlock) {
      let candidates = [...mediaToResume].filter((media) => media.isConnected);
      if (!candidates.length) {
        const replacement = document.querySelector("video, audio");
        if (replacement) candidates = [replacement];
      }
      candidates.forEach((media) => media.play().catch(() => {}));
    }
    mediaToResume.clear();
    resumeMediaAfterBlock = false;
  }
}

document.addEventListener("play", (event) => {
  if (limitUi?.state && Number(limitUi.state.remaining) <= 0) {
    try {
      mediaToResume.add(event.target);
      resumeMediaAfterBlock = true;
      event.target.pause();
    } catch (_) {}
  }
}, true);

function bridgeMessage(message, fallback = {}) {
  try {
    if (!chrome.runtime?.id) return Promise.resolve(fallback);
    return chrome.runtime.sendMessage(message).catch(() => fallback);
  } catch (_) {
    // An unpacked-extension reload invalidates the old page context until the
    // tab is refreshed. Never leave a repeating console error behind.
    return Promise.resolve(fallback);
  }
}

function formatDuration(value) {
  const seconds = Math.max(0, Math.ceil(Number(value) || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours) return `${hours} h ${String(minutes).padStart(2, "0")} min ${String(rest).padStart(2, "0")} s`;
  return minutes ? `${minutes} min ${String(rest).padStart(2, "0")} s` : `${rest} s`;
}

function ensureLimitUi() {
  if (limitUi) {
    if (!limitUi.banner.isConnected || !limitUi.overlay.isConnected) {
      (document.documentElement || document).append(limitUi.overlay, limitUi.banner);
    }
    return limitUi;
  }
  const banner = document.createElement("aside");
  const label = document.createElement("span");
  const bonus = document.createElement("button");
  const countdown = document.createElement("strong");
  const progress = document.createElement("div");
  const fill = document.createElement("div");
  const overlay = document.createElement("div");
  banner.id = "usage-guard-limit-banner";
  banner.style.cssText = [
    "display:none", "position:fixed", "z-index:2147483647", "top:0", "left:0", "right:0",
    "box-sizing:border-box", "min-height:40px", "padding:8px 14px",
    "align-items:center", "gap:10px", "white-space:nowrap",
    "background:rgba(100,18,24,.62)", "color:white", "font:600 14px system-ui,sans-serif",
    "box-shadow:0 2px 8px #0005", "pointer-events:none", "user-select:none"
  ].join(";");
  label.style.cssText = "flex:0 1 auto;overflow:hidden;text-overflow:ellipsis";
  countdown.style.cssText = "flex:0 0 auto;font-variant-numeric:tabular-nums";
  bonus.style.cssText = [
    "display:none", "flex:0 0 auto", "padding:5px 10px",
    "border:1px solid #ffb3b3", "border-radius:5px", "background:#68181e",
    "color:white", "font:600 12px system-ui,sans-serif", "cursor:pointer", "pointer-events:auto"
  ].join(";");
  progress.style.cssText = "flex:1 1 160px;min-width:60px;height:5px;overflow:hidden;border-radius:99px;background:#65191e";
  fill.style.cssText = "height:100%;width:0;background:#ff6b6b;transition:width .35s linear";
  overlay.style.cssText = [
    "display:none", "position:fixed", "z-index:2147483646", "top:48px", "right:0",
    "bottom:0", "left:0", "background:#180607f2", "backdrop-filter:blur(7px)",
    "cursor:not-allowed"
  ].join(";");
  progress.append(fill);
  banner.append(label, progress, countdown, bonus);
  (document.documentElement || document).append(overlay, banner);
  bonus.addEventListener("click", async () => {
    if (!limitUi?.state) return;
    bonus.disabled = true;
    bonus.textContent = tr("extensionPending");
    const result = await bridgeMessage({
      type: "usage-guard-grant-extension",
      targetKey: limitUi.state.target_key
    }, {accepted: false});
    if (!result?.accepted) bonus.disabled = false;
  });
  limitUi = {banner, label, bonus, countdown, fill, overlay, state: null};
  return limitUi;
}

function renderLimit(state) {
  const ui = ensureLimitUi();
  ui.state = state;
  if (!state) {
    setMediaBlocked(false);
    ui.banner.style.display = "none";
    ui.overlay.style.display = "none";
    return;
  }
  const allowed = Math.max(1, Number(state.allowed) || 1);
  const remaining = Math.max(0, Number(state.remaining) || 0);
  const blocked = remaining <= 0;
  setMediaBlocked(blocked);
  ui.banner.style.display = "flex";
  ui.label.textContent = blocked ? `${state.label} — ${tr("timeElapsed")}` : state.label;
  ui.countdown.textContent = formatDuration(remaining);
  ui.fill.style.width = `${Math.min(100, 100 * (Number(state.seconds) || 0) / allowed)}%`;
  ui.overlay.style.display = blocked ? "block" : "none";
  ui.bonus.disabled = false;
  ui.bonus.textContent = tr("getExtension", formatDuration(state.extension_seconds));
  ui.bonus.style.display = blocked && !state.extension_used ? "inline-block" : "none";
}

function notifyUsageGuard() {
  if (!document.hidden) {
    bridgeMessage({type: "usage-guard-active-tab"});
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "usage-guard-limit-state") renderLimit(message.state || null);
});

document.addEventListener("visibilitychange", notifyUsageGuard);
window.addEventListener("focus", notifyUsageGuard);
setInterval(notifyUsageGuard, 1000);
notifyUsageGuard();
