"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const root = path.resolve(__dirname, "..");
const documentElement = {
  nodeType: 1,
  lang: "fr",
  hasAttribute: () => false,
};
const context = {
  console,
  navigator: { language: "en-GB" },
  localStorage: { getItem: () => "en", setItem: () => {} },
  Node: { TEXT_NODE: 3, ELEMENT_NODE: 1 },
  NodeFilter: { SHOW_ELEMENT: 1, SHOW_TEXT: 4 },
  document: {
    documentElement,
    addEventListener: () => {},
    createTreeWalker: () => ({ nextNode: () => false }),
  },
  window: {},
};
context.globalThis = context;
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(root, "pwa", "i18n.js"), "utf8"), context);

context.window.UG_I18N.setLanguage("en");
const translate = context.window.UG_I18N.translate;
const cases = new Map([
  ["Activités du jour", "Today's activities"],
  ["Classement", "Classification"],
  ["Sessions Windows du jour", "Today's Windows sessions"],
  ["Politique enregistrée · 2 ordinateur(s) en attente", "Policy saved · 2 computer(s) pending"],
  ["Dernière modification : 25/08/2026 23:10", "Last changed: 25/08/2026 23:10"],
  ["Session Windows 3", "Windows session 3"],
  ["Supprimer l’utilisateur nicklaus ?", "Delete user nicklaus?"],
  ["La mise à jour va fermer la PWA locale pendant l’installation. Continuer ?", "The update will close the local PWA during installation. Continue?"],
]);

const failures = [];
for (const [source, expected] of cases) {
  const actual = translate(source);
  if (actual !== expected) failures.push({ source, expected, actual });
}
if (context.window.UG_I18N.locale() !== "en-GB") {
  failures.push({ source: "locale", expected: "en-GB", actual: context.window.UG_I18N.locale() });
}
if (failures.length) {
  console.error(JSON.stringify(failures, null, 2));
  process.exit(1);
}
console.log(`PWA runtime translations checked: ${cases.size}`);
