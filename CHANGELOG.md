# Journal des versions

## Développement local

15/08/2026 14:35 — développement local — Dans la PWA distante, l’onglet Paramètres reste visible mais ne montre aucun contenu aux comptes non administrateurs ; les administrateurs n’y voient que la gestion des utilisateurs.
15/08/2026 14:30 — documentation — The target architecture reference is now fully written in English and has been checked for sensitive information.
15/08/2026 14:25 — build local — Le contrôle de relance identifie désormais directement le chemin de l’exécutable lancé, sans faux échec « chemin inconnu ».
15/08/2026 14:15 — développement local — Dans « Dernière session Windows », chaque niveau est trié par temps d’utilisation décroissant ; un ordre manuel enregistré reste prioritaire pour les catégories concernées.
15/08/2026 13:55 — développement local — Audit avant publication : secrets et dépendances contrôlés, fichiers d’exploitation privés retirés de Git, journaux désactivés par défaut, APIs limitées au loopback, origine du pont navigateur vérifiée, jetons d’URL supprimés et HTML dynamique échappé.
15/08/2026 13:35 — développement local — README anglais réécrit avec une présentation précise du fonctionnement, des limites, notifications, interfaces, extension navigateur, données et architecture future, sans procédure de compilation ; build_exe.py est exclu de Git.
15/08/2026 13:20 — développement local — Arrêt des évolutions fonctionnelles pour une passe de traduction : catalogue anglais du programme et du systray complété, choix de langue désormais appliqué immédiatement à la PWA et textes chargés dynamiquement traduits.
15/08/2026 12:55 — développement local — Seuils de notification par durée ou horaire et par cible choisie dans l’arborescence réelle, avec les catégories de sites sous le navigateur renommé, validité permanente ou datée et suppression limitée aux échéances effectivement expirées. Les préavis affichent désormais toutes leurs durées, avec ajout, modification et activation groupée sans remplacement des valeurs existantes.
15/08/2026 12:44 — développement local — La création d’un préavis global avant les limites ne recherche plus une limite individuelle inexistante et s’enregistre correctement.
15/08/2026 12:36 — développement local — Le déploiement valide désormais ses paramètres avant exécution et affiche une erreur courte, lisible et précise à la place du code 2 et de la pile PowerShell.
15/08/2026 12:28 — développement local — La limitation de tout l’ordinateur dispose désormais du même bouton compact ON/OFF que les autres limites, en conservant sa planification et son auteur lorsqu’elle est désactivée.
15/08/2026 12:20 — développement local — Activation et désactivation des limitations et notifications accessibles par des boutons compacts verts ou rouges directement dans chaque carte.
15/08/2026 12:14 — développement local — Infobulle du systray recentrée sur la seule liste des limitations du jour, avec un titre explicite et sans résumé du temps actif.
15/08/2026 12:06 — développement local — Déplacement des catégories et sous-catégories de sites rendu directement accessible par un bouton et un choix précis avant ou après tout élément du même niveau.
15/08/2026 11:58 — développement local — Toutes les saisies de durée proposent désormais une valeur accompagnée d’une unité Minutes ou Heures.
15/08/2026 11:50 — build local — Gestion explicite de plusieurs préavis avant limite, avec liste des délais configurés, ajout rapide et validation renforcée. Le build referme aussi toute ancienne instance relancée pendant la compilation.

20/06/2026 21:01 — v0.1 — Première preuve de concept.
20/06/2026 21:10 — git `03ee18f` — Statut expérimental de la v0.1 précisé.
20/06/2026 21:14 — git `db33429` — ActivityWatch ajouté aux prérequis.
03/08/2026 08:36 — git `3e38ac6` — Suivi d’activité et catégories améliorés.
03/08/2026 10:11 — git `6e2556d` — Statistiques persistantes et suivi multimédia corrigés.
03/08/2026 10:16 — git `c4952e6` — Exclusion des usages multimédias passifs ajoutée.
03/08/2026 10:19 — git `11b459e` — Temps d’allumage du PC ajouté.
03/08/2026 12:41 — git `ec2e113` — Arbre des activités et suivi améliorés.
03/08/2026 13:02 — git `e744656` — Attribution de YouTube Shelf corrigée.
04/08/2026 07:39 — git `3d1c782` — Catégories et sites du navigateur améliorés.
04/08/2026 20:06 — git `7046b12` — Démarrage depuis la barre système rendu plus fluide.
09/08/2026 15:14 — git `9ec7f41` — Sélection d’une date ajoutée aux usages.
13/08/2026 00:57 — git `8fbdd8a` — Premières limites et base de la PWA distante.
13/08/2026 01:05 — git `66114ea` — Tableau de bord remplacé par la PWA locale.
13/08/2026 01:30 — git `45ed129` — Limites corrigées et historique protégé.
13/08/2026 01:45 — git `1507cb0` — Ouverture du tableau de bord dans Brave.
13/08/2026 01:54 — git `ff5dcaf` — Arbre interactif restauré dans la PWA.
13/08/2026 02:09 — git `ba465b2` — Analyse par catégorie et progression ajoutées.
13/08/2026 02:16 — git `b16ea4a` — Placement des notifications amélioré.
13/08/2026 02:23 — git `daa11e4` — Cibles multimédias mises en évidence.
13/08/2026 02:28 — git `40949bb` — Interface PWA simplifiée en listes.
13/08/2026 02:30 — git `88fd25f` — Fenêtre de progression rendue opaque.
13/08/2026 02:46 — git `cc3e5c8` — Annulation des formulaires invalides corrigée.
13/08/2026 02:52 — git `ec9938f` — Onglet d’organisation redondant retiré.
14/08/2026 00:36 — git `ef2bff7` — Backend distant et suivi des sessions consolidés.
15/08/2026 07:27 — build local — Infobulle système corrigée et suppression définitive des limites respectée après redémarrage ou recompilation.
15/08/2026 07:44 — build local — Création de limite séparée entre catégorie et activité directe, avec annulation rapide généralisée aux parcours progressifs.
15/08/2026 07:52 — build local — Navigation uniformisée sur « Retour » dans tous les parcours et formulaires.
15/08/2026 08:01 — build local — Assistants normalisés avec un unique bouton « Retour » placé après les choix.
15/08/2026 08:08 — build local — Limitation de l’ordinateur planifiable avec saisies directes et catégories techniques masquées.
15/08/2026 08:22 — build local — Notifications configurables et limite horaire par application ou catégorie ajoutées.
15/08/2026 08:47 — build local — Planification des limites par jour précis et plage horaire, formulaires détaillés et état vide retiré.
15/08/2026 08:52 — build local — Réorganisation visuelle des catégories rendue accessible par poignée ou menu contextuel, sans changement de niveau.
15/08/2026 09:10 — build local — Rafraîchissement stabilisé : les compteurs restent à jour sans reconstruire ni faire pulser les frises ouvertes.
15/08/2026 09:12 — développement local — Blocage de l’ordinateur à une heure précise pour un jour ou une durée aujourd’hui, auteur ajouté aux notifications et cache PWA fiabilisé pour les mises à jour.
15/08/2026 09:30 — développement local — Grille des catégories réparée et toutes les notifications rendues exclusivement dépendantes des règles créées dans l’onglet Notifications.
15/08/2026 09:55 — développement local — Blocage de l’ordinateur défini par une heure de début et une heure de fin, sans saisie de durée.
15/08/2026 10:15 — développement local — Création des limites unifiée par cible, avec validité permanente, date de début et date de fin.
15/08/2026 10:25 — développement local — Heures de début et de fin ajoutées aux bornes datées de validité des limitations.
15/08/2026 11:00 — développement local — Applications proposées au démarrage corrigées et préavis multiples permis pour l’ordinateur, une catégorie ou une activité.
15/08/2026 11:15 — développement local — Notifications de démarrage et préavis rendus globaux, avec création toujours active et sans choix d’état final.
15/08/2026 11:25 — développement local — Limitations de tout l’ordinateur toujours affichées dans l’infobulle système, y compris avant ou hors de leur plage horaire.
15/08/2026 11:35 — développement local — Arrêt des processus PyInstaller effectué par arbre complet afin d’éviter les avertissements de nettoyage des dossiers temporaires `_MEI`.

## Publications serveur

13/08/2026 13:15 — v1.001 — Première mise en ligne du backend et de la PWA distante.
13/08/2026 13:21 — v1.002 — Installation serveur, Apache et Fail2ban automatisés.
13/08/2026 13:43 — v1.003 — Comptes distants et connexion sécurisée ajoutés.
13/08/2026 13:45 — v1.004 — Restauration automatique d’Apache corrigée.
13/08/2026 13:51 — v1.005 — Exclusion des autres sites de Brave corrigée.
13/08/2026 15:00 — v1.006 — Rôles et droits des comptes ajoutés.
13/08/2026 17:11 — v1.007 — Frise d’une activité accessible depuis l’arbre.
13/08/2026 17:15 — v1.008 — Heure d’ouverture des applications précisée.
13/08/2026 17:19 — v1.009 — Date du jour et création de limite ajoutées.
13/08/2026 17:49 — v1.010 — Résumé de session et frises intégrées améliorés.
13/08/2026 18:03 — v1.011 — Historique graphique et stockage distant ajoutés.
13/08/2026 18:07 — v1.012 — Compte actif et déconnexion ajoutés à l’en-tête.
13/08/2026 18:26 — v1.013 — Détection de l’accès distant corrigée.
13/08/2026 18:46 — v1.014 — Administration des rôles et droits améliorée.
13/08/2026 18:52 — v1.015 — Répartition visuelle de la session ajoutée.
13/08/2026 19:05 — v1.016 — Affichage du compte et de la session corrigé.
13/08/2026 19:11 — v1.017 — Analyse chronologique d’une session ajoutée.
13/08/2026 19:19 — v1.018 — Frises regroupées et adaptées aux petits écrans.
13/08/2026 19:27 — v1.019 — Événements d’ouverture et de fermeture ajoutés.
13/08/2026 19:29 — v1.020 — Horaires de la chronologie corrigés.
13/08/2026 19:41 — v1.021 — Fin de session et instant présent mieux indiqués.
13/08/2026 22:42 — v1.022 — Chronologie redessinée et activité actuelle signalée.
13/08/2026 23:02 — v1.023 — Mise à jour automatique de la PWA ajoutée.
13/08/2026 23:46 — v1.024 — Affichage dynamique adapté à la sécurité distante.
13/08/2026 23:49 — v1.025 — Politique de sécurité des styles corrigée.
14/08/2026 12:26 — v1.026 — Notifications et interdiction globale du PC ajoutées.
14/08/2026 12:54 — v1.027 — Déploiement serveur automatisé et textes précisés.
14/08/2026 13:23 — v1.028 — Déplacement vers une catégorie ajouté.
14/08/2026 13:39 — v1.029 — Défilement automatique pendant un déplacement ajouté.
14/08/2026 14:03 — v1.030 — Statistiques par cible et période ajoutées.
14/08/2026 16:19 — v1.031 — Réorganisation des catégories améliorée.
14/08/2026 21:54 — v1.032 — Doublons et totaux des sites spécifiques corrigés.
14/08/2026 22:17 — v1.033 — Résumé de session et panneaux simplifiés.
14/08/2026 22:31 — v1.034 — Menus guidés pour analyses et notifications ajoutés.
15/08/2026 06:44 — v1.035 — Création des limites et notifications guidée étape par étape.
15/08/2026 07:27 — v1.036 — Paramètres restructurés, analyse replacée au-dessus du graphique, préavis configurables et auteurs des changements de limites affichés.
15/08/2026 07:44 — v1.037 — Choix explicite entre catégorie et activité directe, avec boutons d’annulation et touche Échap dans les parcours progressifs.
15/08/2026 08:10 — v1.038 — Navigation unifiée avec un seul bouton Retour, saisies directes, limitation par durée ou heure, notifications configurables et catégories techniques masquées.
15/08/2026 08:47 — v1.039 — Limites planifiées par jour et plage horaire, blocage à heure précise, notifications configurables avec auteur, catégories réorganisables et frises stabilisées.
15/08/2026 10:30 — v1.040 — Cibles de limite unifiées, validité datée à l’heure près, plages horaires, notifications configurables, catégories et frises stabilisées.
15/08/2026 11:25 — v1.041 — Notifications globales au démarrage et avant les limites, créations toujours actives et limites ordinateur toujours visibles dans le systray.
15/08/2026 11:47 — v1.042 — Durées en minutes ou heures, réorganisation des catégories, infobulle du systray centrée sur les limites et boutons compacts d’activation.
15/08/2026 12:01 — v1.043 — Préavis multiples et globaux corrigés, unités de durée, catégories réorganisables, systray simplifié, boutons ON/OFF pour toutes les limites et déploiement fiabilisé.
15/08/2026 12:46 — v1.044 — Seuils par durée ou horaire, cibles hiérarchiques, validité datée, échéances expirées supprimées et préavis multiples regroupés.
