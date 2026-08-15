(() => {
  "use strict";

  const exact = new Map(Object.entries({
    "Accès distant sécurisé": "Secure remote access",
    "Connexion": "Sign in",
    "Identifiant": "Username",
    "Mot de passe": "Password",
    "Se connecter": "Sign in",
    "Se déconnecter": "Sign out",
    "Choisir votre mot de passe": "Choose your password",
    "Le mot de passe temporaire doit être remplacé avant de continuer.": "The temporary password must be replaced before continuing.",
    "Mot de passe temporaire": "Temporary password",
    "Nouveau mot de passe": "New password",
    "Confirmer": "Confirm",
    "Enregistrer": "Save",
    "Sections": "Sections",
    "Dernière session Windows": "Latest Windows session",
    "Session en cours": "Current session",
    "Répartition de la session Windows": "Windows session breakdown",
    "Actif": "Active",
    "Passif": "Passive",
    "Chronologie relative": "Relative timeline",
    "Initialisation du journal horaire…": "Initializing timeline…",
    "Détection des applications visibles et des sessions multimédias": "Detecting visible applications and media sessions",
    "Analyse": "Analysis",
    "Limites": "Limits",
    "Notifications": "Notifications",
    "Paramètres": "Settings",
    "Faire une analyse": "Run an analysis",
    "Application ou catégorie": "Application or category",
    "Total, moyenne et détail par jour": "Total, average and daily breakdown",
    "Session Windows": "Windows session",
    "Frise chronologique détaillée": "Detailed timeline",
    "← Retour": "← Back",
    "Catégories": "Categories",
    "Applications et sites": "Applications and websites",
    "Aujourd’hui": "Today",
    "7 derniers jours": "Last 7 days",
    "30 derniers jours": "Last 30 days",
    "Toute la période": "Entire period",
    "Choisir les dates": "Choose dates",
    "Date de début": "Start date",
    "Date de fin": "End date",
    "Analyser": "Analyze",
    "Temps actif": "Active time",
    "Afficher moins de jours": "Show fewer days",
    "Afficher plus de jours": "Show more days",
    "Zoom avant": "Zoom in",
    "Zoom arrière": "Zoom out",
    "Tout": "All",
    "Nouvelle limitation": "New limitation",
    "Validité permanente": "Permanent validity",
    "La règle reste active sans date de fin": "The rule remains active without an end date",
    "Définir une période": "Set a period",
    "À partir d’une date, jusqu’à une date, ou les deux": "From a date, until a date, or both",
    "Période de validité": "Validity period",
    "À partir du": "From",
    "Jusqu’au": "Until",
    "À": "At",
    "Renseignez au moins une date avec son heure. Les deux bornes sont incluses.": "Enter at least one date and time. Both boundaries are inclusive.",
    "Continuer": "Continue",
    "Durée quotidienne": "Daily duration",
    "Temps autorisé par jour": "Time allowed per day",
    "Valeur de la durée": "Duration value",
    "Unité de la durée": "Duration unit",
    "Minutes": "Minutes",
    "Heures": "Hours",
    "Cette durée est comptée uniquement quand la limitation est active.": "This duration is counted only while the limitation is active.",
    "Planification de la limitation": "Limitation schedule",
    "De": "From",
    "Si une plage est indiquée, la durée est comptée et appliquée uniquement pendant cette plage, chaque jour de la période de validité.": "When a time range is set, usage is counted and restricted only during that range on each day of the validity period.",
    "Interdire après cette heure (facultatif)": "Restrict after this time (optional)",
    "Exemple : 23:00. Le préavis défini à l’étape précédente sera utilisé.": "Example: 23:00. The warning configured in the previous step will be used.",
    "Heure de début": "Start time",
    "Heure de fin": "End time",
    "La limitation sera active entre ces deux heures pendant toute sa période de validité.": "The limitation will be active between these times throughout its validity period.",
    "Nouvelle notification": "New notification",
    "Au démarrage d’une application limitée": "When a limited application starts",
    "Si une limite est ajoutée ou modifiée": "When a limit is added or changed",
    "Prévenir avant la limite": "Warn before the limit",
    "Si une limitation de l’ordinateur est modifiée": "When a computer limitation changes",
    "Si quelqu’un se connecte à la PWA": "When someone signs in to the PWA",
    "Au dépassement d’un seuil": "When a threshold is exceeded",
    "Type de seuil": "Threshold type",
    "Durée d’utilisation": "Usage duration",
    "Prévenir après une durée définie": "Notify after a set duration",
    "Horaire": "Time",
    "Prévenir après une certaine heure": "Notify after a set time",
    "Seuil de durée": "Duration threshold",
    "Prévenir après": "Notify after",
    "Seuil horaire": "Time threshold",
    "Prévenir après cette heure": "Notify after this time",
    "Validité de la notification": "Notification validity",
    "La notification reste active sans date de fin": "The notification remains active without an end date",
    "Une notification arrivée en fin de validité sera supprimée automatiquement.": "A notification that reaches the end of its validity period will be deleted automatically.",
    "Valeur du délai": "Warning value",
    "Unité du délai": "Warning unit",
    "Ajouter": "Add",
    "Options générales": "General options",
    "Langue": "Language",
    "Langue du programme principal": "Main application language",
    "Automatique (langue système)": "Automatic (system language)",
    "Français": "French",
    "Le changement sera appliqué au prochain redémarrage d’Usage Guard.": "The desktop application will use this language after its next restart.",
    "Thème": "Theme",
    "Apparence de l’interface": "Interface appearance",
    "Automatique (thème système)": "Automatic (system theme)",
    "Sombre": "Dark",
    "Clair": "Light",
    "Utilisateurs": "Users",
    "Compte distant": "Remote account",
    "Changer le mot de passe": "Change password",
    "Mot de passe actuel": "Current password",
    "Administration": "Administration",
    "Rôles et droits des utilisateurs distants": "Remote user roles and permissions",
    "Chargement…": "Loading…",
    "Votre compte n’est pas administrateur. Ce rôle peut être attribué depuis la PWA locale sur le PC Usage Guard.": "Your account is not an administrator. This role can be assigned from the local PWA on the Usage Guard PC.",
    "Utilisateurs distants": "Remote users",
    "Création autorisée uniquement depuis ce PC": "Users can only be created from this PC",
    "Actualiser": "Refresh",
    "Créer un utilisateur": "Create user",
    "Valeurs par défaut": "Default values",
    "Réglages appliqués aux nouvelles limitations": "Settings applied to new limitations",
    "Préavis avant la fin du temps autorisé": "Warning before allowed time ends",
    "Choisissez une valeur et son unité": "Choose a value and its unit",
    "Valeur du préavis par défaut": "Default warning value",
    "Unité du préavis par défaut": "Default warning unit",
    "Modifier": "Edit",
    "Fermer": "Close",
    "Retour": "Back",
    "Aucune limitation aujourd’hui": "No limitation today",
    "Limitations aujourd’hui": "Today's limitations",
    "Tout l’ordinateur": "Entire computer",
    "Applications non classées": "Uncategorized applications",
    "Déplacer la catégorie": "Move category",
    "Déplacer la sous-catégorie": "Move subcategory",
    "Réorganiser": "Reorder",
    "Déplier": "Expand",
    "Replier": "Collapse",
    "Active": "Active",
    "Désactivée": "Disabled",
    "Activer": "Enable",
    "Désactiver": "Disable",
    "Modifier": "Edit",
    "Réinitialiser": "Reset",
    "Retirer": "Remove",
    "Planifiée": "Scheduled",
    "Terminée": "Ended",
    "Configurée": "Configured",
    "Lever la limitation": "Remove limitation",
    "Limitation de l’usage de l’ordinateur": "Computer usage limitation",
    "Aucune donnée historique.": "No historical data.",
    "Aucune donnée sur cette période.": "No data for this period.",
    "Aucune session sur cette période.": "No session during this period.",
    "Aucun programme détecté depuis le démarrage.": "No program detected since startup.",
    "Ouvert, non actif": "Open, inactive",
    "Usage actif comptabilisé": "Counted active use",
    "Usage Guard démarre": "Usage Guard starts",
    "Session Windows démarrée": "Windows session started",
    "Temps total": "Total time",
    "Moyenne par jour": "Daily average",
    "Jours d’utilisation": "Days used",
    "Jour le plus actif": "Most active day",
    "Aucune utilisation": "No usage",
    "Langue enregistrée": "Language saved",
    "Thème appliqué": "Theme applied",
    "Préavis par défaut enregistré": "Default warning saved",
    "Modification transmise au PC": "Change sent to the PC",
    "Modification enregistrée": "Change saved",
    "Connexion requise": "Sign-in required",
    "Erreur de communication": "Communication error",
    "Connexion locale momentanément interrompue": "Local connection temporarily interrupted",
    "Association locale impossible": "Local pairing failed",
    "Connexion refusée": "Sign-in denied",
    "Administrateur": "Administrator",
    "Compte actif": "Active account",
    "Mot de passe temporaire à changer": "Temporary password must be changed",
    "Mot de passe personnel défini": "Personal password set",
    "Gérer": "Manage",
    "Aucun utilisateur distant.": "No remote user.",
    "Voir les activités du jour": "View today's activities",
    "Voir l’analyse et l’historique": "View analysis and history",
    "Voir les limitations": "View limitations",
    "Voir les notifications": "View notifications",
    "Modifier/classer les activités": "Edit and classify activities",
    "Créer et modifier les limitations": "Create and edit limitations",
    "Créer et modifier les notifications": "Create and edit notifications",
    "Enregistrer les droits": "Save permissions",
    "Droits enregistrés": "Permissions saved",
    "Rôle et droits enregistrés": "Role and permissions saved",
    "Média en arrière-plan": "Background media",
    "Autres sites": "Other websites",
    "Web": "Web",
    "Multimédia": "Media",
    "Programme": "Program",
    "PWA / site actif": "PWA / active website",
    "Activités exclues": "Excluded activities",
    "Activités sans utilisation aujourd’hui": "Activities with no usage today",
    "Aucune activité sur cette période.": "No activity during this period.",
    "Choisir dans l’arborescence": "Choose from the hierarchy",
    "Ouvrir les sites et leurs catégories": "Open websites and their categories",
    "Choisir toute cette catégorie": "Select this entire category",
    "Site spécifique": "Specific website",
    "Aucune cible disponible.": "No target available.",
    "Aucun choix disponible.": "No option available.",
    "Choisir une cible": "Choose a target",
    "Choisir une catégorie": "Choose a category",
    "Choisir un site spécifique": "Choose a specific website",
    "Choisir une application": "Choose an application",
    "Non classé": "Uncategorized",
    "Catégorie": "Category",
    "Ou nouvelle catégorie": "Or a new category",
    "Nouveau nom": "New name",
    "Nouvelle position": "New position",
    "Renommer l’activité": "Rename activity",
    "Déplacer vers une catégorie…": "Move to a category…",
    "Retirer de la catégorie": "Remove from category",
    "Fusionner dans une autre activité…": "Merge into another activity…",
    "Ne pas comptabiliser": "Do not count",
    "Supprimer définitivement…": "Delete permanently…",
    "Rendre spécifique": "Make specific",
    "Renommer la catégorie…": "Rename category…",
    "Choisir la position…": "Choose position…",
    "Monter dans l’affichage": "Move up",
    "Descendre dans l’affichage": "Move down",
    "Retirer la catégorie": "Remove category",
    "Renommer la sous-catégorie…": "Rename subcategory…",
    "Retirer la sous-catégorie": "Remove subcategory",
    "Renommer le navigateur…": "Rename browser…",
    "Sortir de la catégorie": "Move out of category",
    "Réactiver": "Re-enable",
    "Rallonge exceptionnelle": "Exceptional extension",
    "Durée de la rallonge": "Extension duration",
    "Cette rallonge peut être accordée une fois lorsque la durée autorisée est épuisée.": "This extension can be granted once after the allowed duration is used up.",
    "Préavis avant blocage": "Warning before restriction",
    "Prévenir combien de temps avant ?": "How long before should a warning be sent?",
    "Une notification sera envoyée avant la fin de la durée ou de l’heure autorisée.": "A notification will be sent before the allowed duration or time ends.",
    "Nouveau délai avant toutes les limites": "New warning for all limits",
    "Prévenir avant la limitation": "Warn before the limitation",
    "Durées configurées": "Configured durations",
    "Aucun préavis configuré.": "No warning configured.",
    "+ Ajouter une durée": "+ Add a duration",
    "Modifier cette durée": "Edit this duration",
    "Toutes les applications limitées": "All limited applications",
    "Toutes les limites": "All limits",
    "Démarrage": "Startup",
    "Ajout, modification ou suppression d’une limite": "Limit added, changed, or removed",
    "Ajout, modification ou levée d’une limitation de l’ordinateur": "Computer limitation added, changed, or removed",
    "Connexion réussie à la PWA": "Successful PWA sign-in",
    "Seuil dépassé": "Threshold exceeded",
    "Durée": "Duration",
    "Validité permanente": "Permanent validity",
    "Indiquez une durée valide": "Enter a valid duration",
    "Indiquez un délai valide": "Enter a valid warning",
    "Indiquez une heure": "Enter a time",
    "Indiquez au moins une date et une heure": "Enter at least one date and time",
    "Chaque date doit être accompagnée de son heure": "Each date must include a time",
    "La fin de validité doit être après son début": "The validity end must be after its start",
    "Indiquez le début et la fin de la plage horaire": "Enter the start and end of the time range",
    "La fin de la plage doit être après son début": "The time range must end after it starts",
    "L’heure de fin doit être après l’heure de début": "The end time must be after the start time",
    "Indiquez un préavis valide": "Enter a valid warning",
    "Préavis activés": "Warnings enabled",
    "Préavis désactivés": "Warnings disabled",
    "Préavis supprimés": "Warnings deleted",
    "Utilisateur créé": "User created",
    "Utilisateur supprimé": "User deleted",
    "Mot de passe modifié": "Password changed",
    "Les mots de passe sont différents": "Passwords do not match",
    "Les deux nouveaux mots de passe sont différents": "The two new passwords do not match"
  }));

  const patterns = [
    [/^(\d+) jours$/, "$1 days"],
    [/^(.+) écoulées$/, "$1 elapsed"],
    [/^(\d+) programme(s?)$/, "$1 program$2"],
    [/^(\d+) session(s?) ouverte(s?)$/, "$1 open session$2"],
    [/^Enregistrement horaire actif · (.+)$/, "Timeline recording active · $1"],
    [/^(\d+) PWA\/site(s?) ouvert(s?)$/, "$1 open PWA/website$2"],
    [/^(\d+) session(s?) multimédia$/, "$1 media session$2"],
    [/^Déplacer la catégorie (.+)$/, "Move category $1"],
    [/^Déplacer la sous-catégorie (.+)$/, "Move subcategory $1"],
    [/^Ouvrir (.+)$/, "Open $1"],
    [/^Avant « (.+) »$/, "Before “$1”"],
    [/^Après « (.+) »$/, "After “$1”"],
    [/^Préavis enregistrés : (.+) · Toutes les limites$/, "Saved warnings: $1 · All limits"],
    [/^reste (.+)$/, "$1 remaining"],
    [/^Préavis (.+) avant la fin$/, "$1 warning before the end"],
    [/^(.+) utilisés sur (.+)$/, "$1 used out of $2"],
    [/^Interdit après (.+)$/, "Restricted after $1"],
    [/^À partir du (.+)$/, "From $1"],
    [/^Jusqu’au (.+)$/, "Until $1"],
    [/^Du (.+) au (.+)$/, "From $1 to $2"],
    [/^Limitation prévue du (.+) au (.+)\.$/, "Limitation scheduled from $1 to $2."],
    [/^Ordinateur limité jusqu’au (.+)\.$/, "Computer limited until $1."],
    [/^Demandée par (.+)$/, "Requested by $1"],
    [/^Catégorie · (.+)$/, "Category · $1"],
    [/^Application · (.+)$/, "Application · $1"],
    [/^Site · (.+)$/, "Website · $1"],
    [/^Prévenir (.+) avant$/, "Notify $1 before"],
    [/^Après (.+) d’utilisation$/, "After $1 of use"],
    [/^Après (.+)$/, "After $1"],
    [/^Valide (.+)$/, "Valid $1"]
  ];

  const nodeState = new WeakMap();
  const attributeState = new WeakMap();
  let language = "fr";
  let observer;

  function resolved(choice) {
    if (choice === "fr" || choice === "en") return choice;
    return /^en\b/i.test(navigator.language || "fr") ? "en" : "fr";
  }

  function translate(source) {
    if (language !== "en") return source;
    const leading = source.match(/^\s*/)?.[0] || "";
    const trailing = source.match(/\s*$/)?.[0] || "";
    const value = source.trim();
    if (!value) return source;
    let result = exact.get(value);
    if (!result) {
      for (const [pattern, replacement] of patterns) {
        if (pattern.test(value)) { result = value.replace(pattern, replacement); break; }
      }
    }
    return leading + (result || value) + trailing;
  }

  function translateText(node) {
    const current = node.nodeValue || "";
    let stored = nodeState.get(node);
    if (!stored || current !== stored.rendered) stored = { source: current, rendered: current };
    const rendered = translate(stored.source);
    nodeState.set(node, { source: stored.source, rendered });
    if (current !== rendered) node.nodeValue = rendered;
  }

  function translateAttributes(element) {
    let stored = attributeState.get(element) || {};
    for (const name of ["title", "aria-label", "placeholder"]) {
      if (!element.hasAttribute(name)) continue;
      const current = element.getAttribute(name) || "";
      const previous = stored[name];
      const source = previous && current === previous.rendered ? previous.source : current;
      const rendered = translate(source);
      stored[name] = { source, rendered };
      if (current !== rendered) element.setAttribute(name, rendered);
    }
    attributeState.set(element, stored);
  }

  function apply(root = document.documentElement) {
    if (root.nodeType === Node.TEXT_NODE) translateText(root);
    if (root.nodeType === Node.ELEMENT_NODE) translateAttributes(root);
    const walker = document.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | NodeFilter.SHOW_TEXT);
    while (walker.nextNode()) {
      const node = walker.currentNode;
      if (node.nodeType === Node.TEXT_NODE) translateText(node);
      else translateAttributes(node);
    }
    document.documentElement.lang = language;
  }

  function setLanguage(choice = "auto") {
    language = resolved(choice);
    localStorage.setItem("usage-guard-language", choice);
    observer?.disconnect();
    apply();
    observer?.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["title", "aria-label", "placeholder"] });
  }

  document.addEventListener("DOMContentLoaded", () => {
    observer = new MutationObserver(records => {
      observer.disconnect();
      for (const record of records) {
        if (record.type === "characterData") translateText(record.target);
        else if (record.type === "attributes") translateAttributes(record.target);
        else for (const node of record.addedNodes) apply(node);
      }
      observer.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ["title", "aria-label", "placeholder"] });
    });
    setLanguage(localStorage.getItem("usage-guard-language") || "auto");
  });

  document.addEventListener("change", event => {
    if (event.target?.id === "language-choice") setLanguage(event.target.value);
  }, true);

  window.UG_I18N = { setLanguage, locale: () => language === "en" ? "en-GB" : "fr-FR", translate };
})();
