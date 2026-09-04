const domains = document.querySelector("#domains");
const status = document.querySelector("#status");

chrome.storage.sync.get({customDomains: ""}, ({customDomains}) => {
  domains.value = customDomains;
});

document.querySelector("#save").addEventListener("click", () => {
  chrome.runtime.sendMessage({type: "save-custom-domains", domains: domains.value}, (result) => {
    status.textContent = result?.ok
      ? "List saved."
      : `Unable to save: ${result?.error || "unknown error"}`;
  });
});
