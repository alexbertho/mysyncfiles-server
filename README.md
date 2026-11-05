# MySyncFiles Server

Ce dépôt contient le serveur, l’interface Atlas et le paquet Rust `mysync-protocol`. Le client Linux et ses releases sont dans [mysyncfiles-client](https://github.com/alexbertho/mysyncfiles-client).

MySyncFiles synchronise un dossier entre appareils Linux. Le serveur conserve les fichiers et arbitre les révisions ; le client préserve les versions locales écartées dans `.mysync-conflicts/`.

> Les données sont en clair sur le serveur et lisibles par son opérateur ou son proxy HTTPS. MySyncFiles n'est pas une sauvegarde et n'a pas encore fait l'objet d'un audit indépendant.

## Démarrage rapide

Il faut Docker Compose et `make` sur le serveur, puis un client Linux x86-64 ou AArch64 avec TPM 2.0 et certificat EK constructeur. Debian 13 et Arch Linux/dérivées sont testés côté client ; le serveur n'a pas besoin de TPM.

**Serveur.** Depuis une copie du dépôt, préparer les dossiers et `deploy/.env` comme indiqué dans le [guide d'installation serveur](docs/install-server.md), puis :

```sh
sh deploy/install-server.sh
make start
```

L’installateur demande un nom d’affichage au serveur. Configurer ensuite le proxy HTTPS et les autorités EK constructeur. Les binaires clients signés sont distribués séparément par le dépôt client.

**Client.** Installer depuis le dépôt client dans un terminal :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://raw.githubusercontent.com/alexbertho/mysyncfiles-client/main/deploy/install.sh | sh
```

L’installateur demande l’URL HTTPS, le dossier local et le Server ID (la clé publique du serveur). Sur le serveur, l'administrateur peut consulter cette clé sans ouvrir d'appairage :

```sh
make get
```

Transmettre le Server ID directement au client par un canal fiable. `make get` affiche aussi le nom, l'origine publique, les appareils approuvés, les invitations en attente et le stockage. Le client affiche ensuite son code ; sur le serveur, lancer :

```sh
make pair
```

Si `make pair` est déjà ouvert pour lire la clé, saisir le code dans ce terminal et le garder ouvert jusqu'à l'approbation. La même demande se reprend avec le même nom et le même code. Un autre code pour un nom réservé propose de remplacer l'invitation en attente après confirmation ; un appareil approuvé exige un autre nom ou la reprise de son profil existant. Le client conserve la clé pour vérifier les réponses du serveur, même derrière un proxy TLS. Pour un profil existant, suivre la [migration de la clé serveur](docs/device-auth.md#authenticite-des-reponses-et-migration).

Après comparaison de l'empreinte TPM, le client effectue une première synchronisation et démarre le service s'il n'y a pas de conflit. Le [guide client](docs/install-client.md) couvre la reprise, le cas du certificat EK externe et le parcours manuel. Une première exécution du script suppose que l'origine HTTPS sert le bon script ; la signature protège le binaire téléchargé, pas un script distant compromis.

## Documentation

- [Guide complet et architecture](docs/index.md)
- [Installation du serveur](docs/install-server.md) et [du client](docs/install-client.md)
- [Explorateur web Atlas](docs/web-files.md) : consulter, rechercher, télécharger, ajouter des fichiers et gérer les dossiers depuis un appareil approuvé
- [Éditeur Python et C](docs/web-code-editor.md) : modifier un fichier synchronisé et l’exécuter sur ce PC, avec des autorisations locales distinctes
- [Statut web et présence locale TPM](docs/web-status.md)
- [Sécurité et limites](docs/security.md), [déploiement](docs/operations.md) et [dépannage](docs/troubleshooting.md)

Pour prévisualiser la documentation localement : `make docs` puis ouvrir `http://127.0.0.1:8000`. `make docs-stop` l'arrête ; `make docs-check` vérifie sa construction. Le service de documentation est optionnel et ne démarre pas le serveur.

Le [guide de déploiement](docs/operations.md#publier-la-documentation) explique comment publier le site statique à `/docs/` sur la même origine HTTPS que l'API.

L’interface web native est dans `web/` et se modifie [à chaud](docs/operations.md#modifier-linterface-web-a-chaud) : sauvegarder le HTML, le CSS ou le JavaScript, puis actualiser le navigateur. Aucun build frontend n’est nécessaire.

## Deux dépôts et plusieurs serveurs

Le client associe un dossier distinct à chaque profil : `mysync --profile maison setup --server https://sync.example.org --dir "$HOME/Sync/maison"`. `mysync daemon --all` synchronise les profils simultanément. Les dossiers égaux ou imbriqués sont refusés.

La version 0.4 exige une mise à jour coordonnée du client et du serveur. Le TPM autorise une clé Ed25519 temporaire conservée en mémoire pendant au plus 15 minutes ; cette clé signe les requêtes de synchronisation. Les autorisations web demandent toujours une preuve TPM fraîche. Voir les [garanties et limites](docs/device-auth.md).

`make test` vérifie le serveur, le protocole et la documentation sans pilote TPM. `make test-integration` exécute séparément les échanges réels avec le client et `swtpm`, avant publication ; voir [les tests](docs/operations.md#tests-et-deploiement).
