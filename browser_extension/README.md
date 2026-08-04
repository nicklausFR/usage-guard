# Usage Guard Browser Bridge

Dans Brave, ouvre `brave://extensions`, active **Mode développeur**, puis
choisis **Charger l’extension non empaquetée** et sélectionne ce dossier.

L’extension ne contacte que `127.0.0.1:8765`, le serveur local démarré par
Usage Guard. Elle transmet uniquement l’URL, le titre et l’état audio de
l’onglet actif.
