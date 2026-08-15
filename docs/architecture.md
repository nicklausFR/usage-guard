# Architecture cible de Usage Guard

## Statut

Décision validée. Ce document sert de référence aux futures tâches Codex et aux évolutions du projet.

## Objectif

Rendre les limitations sensiblement difficiles à contourner pour un utilisateur Windows standard, sans chercher une protection invulnérable face à un administrateur local et sans réécrire l'application existante.

Le produit vise une seule machine surveillée, un seul utilisateur limité et quelques utilisateurs distants. L'architecture doit donc rester simple.

## Principe général

Usage Guard est séparé en deux processus :

1. **UsageGuard Service**, service Windows et autorité de confiance ;
2. **UsageGuard Desktop**, application de session conservant la détection Windows, Qt, le tray et les overlays.

L'extension du navigateur reste un capteur et un mécanisme d'affichage du blocage. Elle ne décide jamais des droits accordés.

```text
Utilisateurs distants / backend
              |
              v
      UsageGuard Service
      - politiques et compteurs
      - stockage protégé
      - décisions autorisé/bloqué
      - surveillance du Desktop
              ^
              | IPC local
              v
      UsageGuard Desktop
      - ActivityProbe
      - interface Qt et tray
      - overlays
      - observation de la session
              ^
              | Native Messaging à terme
              v
      Extension navigateur gérée
```

## UsageGuard Service

Le service est installé une fois avec élévation administrateur. Il fonctionne ensuite indépendamment du compte utilisateur limité.

Il est seul responsable de :

- conserver les politiques et les compteurs de limites ;
- décider si une application ou un site est autorisé ;
- accorder une rallonge validée ;
- recevoir les commandes du backend ;
- stocker l'état sous `%ProgramData%\Usage Guard` avec des ACL adaptées ;
- détecter l'arrêt du Desktop, le relancer et signaler l'interruption ;
- utiliser une horloge monotone pour les durées et détecter les changements incohérents de l'heure système.

Le service ne contient pas de composants Qt et ne tente pas d'afficher directement une interface dans la session Windows.

## UsageGuard Desktop

Le processus Desktop réutilise autant que possible l'implémentation actuelle :

- détection de la fenêtre active et des sessions multimédias ;
- intégration avec le navigateur ;
- tray, notifications et PWA locale ;
- overlays de blocage dans la session utilisateur.

Il transmet les observations au service et applique la décision reçue. Il ne peut pas diminuer, supprimer ou réinitialiser une limite de production.

La PWA locale peut consulter l'état. Les opérations diminuant la protection sont réservées aux utilisateurs distants autorisés.

## Communication locale

La cible est un canal IPC Windows à surface réduite, de préférence un named pipe avec ACL explicites.

Le protocole doit distinguer :

- les observations envoyées par le Desktop ;
- la lecture de l'état ;
- les décisions renvoyées par le service ;
- les commandes d'administration, qui ne doivent pas être accessibles au compte limité.

Les messages et le protocole sont versionnés. L'API HTTP locale existante peut être conservée temporairement pendant la migration, mais ne doit plus donner accès à une commande permettant de diminuer la protection.

## Extension navigateur

L'extension est conservée pour obtenir les informations qu'une application Windows ne peut pas déterminer correctement : onglet actif, URL active et lecture multimédia dans le navigateur.

Son rôle est limité à :

- transmettre l'onglet actif et les informations utiles ;
- demander l'état d'une limite ;
- afficher ou appliquer le blocage demandé.

Elle ne peut jamais accorder une rallonge, remettre un compteur à zéro ou désactiver une limite.

En production :

- l'extension possède un identifiant stable ;
- elle est installée de force par une politique Brave/Chromium placée dans `HKLM` ;
- l'utilisateur standard ne peut ni la désactiver ni la supprimer ;
- les profils invités et les profils non supervisés sont désactivés ;
- les navigateurs sans extension de supervision sont bloqués comme applications ;
- l'absence de heartbeat de l'extension provoque, après un court délai, le blocage du navigateur et un signalement distant.

À court terme, le Browser Bridge HTTP peut être conservé avec authentification et vérification de l'origine. L'endpoint permettant actuellement de demander directement une rallonge doit être supprimé. À terme, la communication doit passer par Native Messaging, puis par l'IPC du service.

## Développement et tests

La logique métier doit être isolée dans un cœur Python sans dépendance directe à Qt, au service Windows ou au réseau.

Ce cœur accepte des adaptateurs :

- adaptateur mémoire pour les tests unitaires ;
- adaptateur local pour le développement rapide dans un seul processus ;
- adaptateur IPC pour la production avec le service Windows.

Les tests unitaires utilisent une horloge simulée, un dossier temporaire et de faux adaptateurs. Seule une petite suite de tests d'intégration démarre réellement le service.

L'environnement de développement est séparé de la production :

- nom d'instance, pipe, ports et dossier de données distincts ;
- extension `Usage Guard Dev` avec un autre identifiant ;
- impossibilité pour l'instance Dev de modifier l'état du service de production.

Le service de production peut continuer à protéger la machine pendant le développement normal. Une fenêtre de maintenance explicite, idéalement autorisée à distance et journalisée, permet les installations et essais nécessitant son arrêt.

## Modèle de menace retenu

La protection vise un utilisateur Windows standard. Elle doit résister aux contournements simples : tuer l'application de tray, modifier un fichier JSON, désactiver l'extension, appeler une API locale ou changer l'heure.

Elle ne prétend pas résister indéfiniment à un administrateur local capable d'arrêter un service, changer les ACL, désinstaller le programme ou démarrer sur un autre système. Dans le contexte où le développeur possède aussi les droits administrateur, l'objectif complémentaire est de rendre les interruptions explicites, volontaires et visibles à distance.

## Migration progressive

1. Authentifier le Browser Bridge et supprimer toute rallonge accordée directement par l'extension.
2. Interdire dans la PWA locale les opérations qui diminuent la protection.
3. Extraire la logique des limites dans un cœur Python testable.
4. Créer le service et son IPC minimal.
5. Déplacer progressivement le stockage, les compteurs et les décisions dans le service.
6. Ajouter le redémarrage du Desktop et les signalements d'interruption.
7. Déployer l'extension gérée par politique navigateur.
8. Remplacer le bridge HTTP par Native Messaging.

Chaque étape doit conserver une application utilisable et une suite de tests simple ; la migration ne doit pas être une réécriture globale.
