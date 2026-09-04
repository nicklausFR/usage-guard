let limitUi = null;
let mediaBlockTimer = null;
let mediaToResume = new Set();
let resumeMediaAfterBlock = false;
let periodicCycleStartedAt = Date.now();
const defaultBannerSettings = {
  mode: "warning", opacity: 62, position: "top",
  warningSeconds: 300, periodicEverySeconds: 300,
  periodicVisibleSeconds: 15
};
let bannerSettings = {...defaultBannerSettings};

function warningOnly(state) {
  return state?.enforcement_action === "warn";
}

function blocksMedia(state) {
  return Boolean(state) && !warningOnly(state) && Number(state.remaining) <= 0;
}

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
  if (blocksMedia(limitUi?.state)) {
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

function pageMediaPlaying() {
  return [...document.querySelectorAll("video, audio")].some((media) => (
    !media.paused && !media.ended && media.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA
  ));
}

function formatDuration(value) {
  const seconds = Math.max(0, Math.ceil(Number(value) || 0));
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const rest = seconds % 60;
  if (hours) return `${hours} h ${String(minutes).padStart(2, "0")} min ${String(rest).padStart(2, "0")} s`;
  return minutes ? `${minutes} min ${String(rest).padStart(2, "0")} s` : `${rest} s`;
}

function formatConfiguredDuration(value, unit) {
  const seconds = Math.max(0, Math.round(Number(value) || 0));
  if (unit === "hours") return `${Number((seconds / 3600).toFixed(2))} h`;
  if (unit === "minutes") return `${Number((seconds / 60).toFixed(2))} min`;
  return formatDuration(seconds);
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

function applyBannerSettings(ui, state) {
  const opacity = Math.min(100, Math.max(15, Number(bannerSettings.opacity) || 62)) / 100;
  const bottom = bannerSettings.position === "bottom";
  ui.banner.style.top = bottom ? "auto" : "0";
  ui.banner.style.bottom = bottom ? "0" : "auto";
  ui.banner.style.background = `rgba(100,18,24,${opacity})`;
  ui.overlay.style.top = bottom ? "0" : "48px";
  ui.overlay.style.bottom = bottom ? "48px" : "0";
  if (!state) return false;
  const remaining = Math.max(0, Number(state.remaining) || 0);
  const reached = remaining <= 0;
  if (reached || bannerSettings.mode === "always") return true;
  if (bannerSettings.mode === "hidden") return false;
  if (bannerSettings.mode === "warning") {
    return remaining <= Math.max(1, Number(bannerSettings.warningSeconds) || 300);
  }
  const every = Math.max(30, Number(bannerSettings.periodicEverySeconds) || 300);
  const visible = Math.min(every, Math.max(3, Number(bannerSettings.periodicVisibleSeconds) || 15));
  const elapsed = Math.max(0, (Date.now() - periodicCycleStartedAt) / 1000);
  return elapsed % every < visible;
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
  const reached = remaining <= 0;
  const blocked = blocksMedia(state);
  setMediaBlocked(blocked);
  ui.banner.style.display = applyBannerSettings(ui, state) ? "flex" : "none";
  ui.label.textContent = reached ? `${state.label} — ${tr("timeElapsed")}` : state.label;
  ui.countdown.textContent = formatDuration(remaining);
  ui.fill.style.width = `${Math.min(100, 100 * (Number(state.seconds) || 0) / allowed)}%`;
  ui.overlay.style.display = blocked ? "block" : "none";
  ui.bonus.disabled = false;
  ui.bonus.textContent = tr(
    "getExtension",
    formatConfiguredDuration(state.extension_seconds, state.extension_unit)
  );
  ui.bonus.style.display = blocked && !state.extension_used && Number(state.extension_seconds) > 0 ? "inline-block" : "none";
}

chrome.storage?.sync?.get(defaultBannerSettings).then((settings) => {
  bannerSettings = {...defaultBannerSettings, ...settings};
  periodicCycleStartedAt = Date.now();
  if (limitUi) renderLimit(limitUi.state);
}).catch(() => {});
chrome.storage?.onChanged?.addListener((changes, area) => {
  if (area !== "sync") return;
  let bannerTimingChanged = false;
  for (const key of Object.keys(defaultBannerSettings)) {
    if (changes[key]) {
      bannerSettings[key] = changes[key].newValue;
      bannerTimingChanged = bannerTimingChanged || [
        "mode", "periodicEverySeconds", "periodicVisibleSeconds"
      ].includes(key);
    }
  }
  if (bannerTimingChanged) periodicCycleStartedAt = Date.now();
  if (limitUi) renderLimit(limitUi.state);
});

function notifyUsageGuard() {
  if (!document.hidden) {
    bridgeMessage({
      type: "usage-guard-active-tab",
      playing: pageMediaPlaying()
    });
  }
}

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "usage-guard-limit-state") renderLimit(message.state || null);
});

document.addEventListener("visibilitychange", notifyUsageGuard);
window.addEventListener("focus", notifyUsageGuard);
for (const eventName of ["play", "pause", "ended", "emptied"]) {
  document.addEventListener(eventName, notifyUsageGuard, true);
}
setInterval(notifyUsageGuard, 1000);
notifyUsageGuard();
