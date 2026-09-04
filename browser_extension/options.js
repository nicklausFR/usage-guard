const defaults={mode:"warning",opacity:62,position:"top",warningSeconds:300,periodicEverySeconds:300,periodicVisibleSeconds:15};
const bounds={opacity:[15,100],warningSeconds:[1,86400],periodicEverySeconds:[30,86400],periodicVisibleSeconds:[3,300]};
const fields=Object.keys(defaults);
function tr(key,substitutions){return chrome.i18n.getMessage(key,substitutions)||key}
function applyTranslations(){document.documentElement.lang=chrome.i18n.getUILanguage().toLowerCase().startsWith("fr")?"fr":"en";document.title=tr("optionsTitle");for(const element of document.querySelectorAll("[data-i18n]"))element.textContent=tr(element.dataset.i18n)}
function clamp(value,[minimum,maximum],fallback){const number=Number(value);return Number.isFinite(number)?Math.min(maximum,Math.max(minimum,Math.round(number))):fallback}
function normalizedValue(key,value){
  if(bounds[key])return clamp(value,bounds[key],defaults[key]);
  if(key==="mode")return ["warning","periodic","always","hidden"].includes(value)?value:defaults[key];
  if(key==="position")return ["top","bottom"].includes(value)?value:defaults[key];
  return defaults[key];
}
function showOpacity(){document.querySelector("#opacity-value").textContent=tr("opacityValue",document.querySelector("#opacity").value)}
function showRelevantFields(){const mode=document.querySelector("#mode").value;document.querySelector("#warning-settings").hidden=mode!=="warning";document.querySelector("#periodic-settings").hidden=mode!=="periodic"}
async function restore(){const saved=await chrome.storage.sync.get(defaults);for(const key of fields)document.querySelector(`#${key}`).value=normalizedValue(key,saved[key]);showOpacity();showRelevantFields()}
let saveTimer=0;
function save(){clearTimeout(saveTimer);saveTimer=setTimeout(async()=>{const value={};for(const key of fields){const input=document.querySelector(`#${key}`);value[key]=normalizedValue(key,input.value)}value.periodicVisibleSeconds=Math.min(value.periodicVisibleSeconds,value.periodicEverySeconds);for(const key of fields)document.querySelector(`#${key}`).value=value[key];showOpacity();await chrome.storage.sync.set(value);document.querySelector("#status").textContent=tr("settingsSaved");setTimeout(()=>document.querySelector("#status").textContent="",1600)},180)}
document.addEventListener("input",event=>{if(event.target.id==="opacity")showOpacity();if(event.target.id==="mode")showRelevantFields();save()});
document.addEventListener("change",event=>{if(event.target.id==="mode")showRelevantFields();save()});
applyTranslations();
restore();
