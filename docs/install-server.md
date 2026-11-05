# Installer le serveur

Le serveur tourne dans Docker Compose derrière un proxy HTTPS. Ces commandes se lancent depuis la racine d'une copie du dépôt sur l'hôte serveur. Docker avec Compose et `make` sont nécessaires ; aucun TPM n'est requis sur cet hôte.

## Préparer le stockage

Copier l'exemple, puis adapter **les trois valeurs** au compte et aux chemins de l'hôte :

```sh
cp deploy/.env.example deploy/.env
${EDITOR:-vi} deploy/.env
```

`MYSYNC_DATA_DIR` contient les fichiers et SQLite et doit être un chemin absolu. Les releases clientes sont hébergées sur le dépôt GitHub client. `MYSYNC_UID` et `MYSYNC_GID` désignent le propriétaire des fichiers dans le conteneur. Ne placer aucune clé privée de signature, invitation ou profil client dans les releases publiques, le dépôt ou la documentation.

Créer les dossiers avant le démarrage. Ces commandes correspondent exactement aux valeurs de `deploy/.env.example` ; adapter chemins, UID et GID si le fichier a été modifié :

```sh
sudo install -d -m 0700 -o 1000 -g 1000 /srv/mysyncfiles
```

`deploy/.env` est ignoré par Git. Conserver le répertoire de données et ses sauvegardes hors du dépôt. Voir la [configuration](configuration.md) pour le rôle de chaque valeur.

## Prévoir du swap sur un petit VPS

`make install` et `make deploy` compilent le serveur en Rust. Sur un VPS avec peu de RAM et sans swap, prévoir par exemple 2 Gio de swap avant la première compilation. Le build conserve sa limite mémoire de 3 Gio ; le swap donne une marge aux autres services de l'hôte. Vérifier la mémoire et le système de fichiers de la racine :

```sh
free -h
findmnt -no FSTYPE /
```

Si aucun swap n'est actif, que `/swapfile` n'existe pas et que la racine est en `ext4`, créer un fichier de swap puis l'activer au démarrage :

```sh
test ! -e /swapfile &&
sudo cp -p /etc/fstab "/etc/fstab.pre-swap.$(date +%Y%m%d%H%M%S)" &&
sudo install -m 0600 /dev/null /swapfile &&
sudo fallocate -l 2G /swapfile &&
sudo mkswap /swapfile &&
sudo swapon /swapfile &&
printf '/swapfile none swap defaults 0 0\n' | sudo tee -a /etc/fstab &&
free -h
```

Sur Btrfs, la création d'un fichier de swap exige des précautions particulières : suivre la [procédure Btrfs](https://btrfs.readthedocs.io/en/latest/Swapfile.html) au lieu des commandes `ext4` ci-dessus.

## Construire et démarrer

```sh
sh deploy/install-server.sh
make start
curl -fsS http://127.0.0.1:8484/v1/health
```

Le script demande un nom d’affichage (ou lit `MYSYNC_SERVER_NAME`), construit le serveur puis enregistre ce nom dans sa base. Le nom apparaît dans Atlas et dans la réponse authentifiée `/v1/server` ; il ne remplace ni l’URL ni la clé épinglée. Hors Docker : `mysync-server init --data-dir DOSSIER --name "Maison"`.

`make install` valide la configuration Compose, l'existence des dossiers et leurs chemins absolus, puis construit l'image avec une limite mémoire. `make start` refait ces vérifications et lance l'image déjà construite sans déclencher de compilation ; le serveur initialise SQLite dans le dossier de données. Le point de santé est accessible uniquement sur la boucle locale de l'hôte. Pour consulter les journaux ou arrêter sans effacer les données : `make logs` et `make stop`.

Pour déployer ensuite des modifications du serveur et de la documentation, utiliser `make deploy` après avoir configuré l'origine publique avec `device auth-configure`. La commande exécute les tests avant de reconstruire et de relancer le serveur ; voir le [détail du déploiement](operations.md#publier-la-documentation).

Les retouches de l’interface HTML/CSS/JavaScript se font directement dans `web/`, monté en lecture seule par Compose. Après le déploiement initial de cette version, une actualisation du navigateur suffit ; voir les [modifications à chaud](operations.md#modifier-linterface-web-a-chaud).

Les commandes directes `docker compose -f deploy/compose.yaml ...` restent disponibles. Ne jamais lancer deux serveurs sur la même base SQLite.

## Exposer une origine HTTPS

Configurer un proxy TLS qui transmet les requêtes vers `127.0.0.1:8484`, sans redirection vers HTTP. L'exemple `deploy/nginx-sync.conf` illustre le proxy HTTP **derrière une terminaison TLS** ; il ne fournit pas lui-même HTTPS et ne doit pas être exposé seul sur Internet. Garder intacts méthode, chemin, query, corps et en-têtes `Authorization` et `x-mysync-proof`. Désactiver le cache et les transformations des routes authentifiées. Les transferts par blocs de 8 Mio restent compatibles avec un proxy Cloudflare, qui peut néanmoins lire les fichiers si TLS s'y termine.

Utiliser ensuite l'[origine publique et les racines EK vérifiées](device-auth.md#configuration-du-serveur) pour exécuter `device auth-configure`. L'origine doit être l'URL HTTPS exacte vue par les clients, sans sous-chemin. Cette configuration est indispensable avant tout appairage.

## Préparer le premier client

[Publier un binaire signé](operations.md#publier-un-client-signe) pour chaque architecture cliente utilisée. Cette publication est une opération distincte de `make install` et `make start`. Tant qu'aucune release compatible n'est publiée, le script d'installation ne peut pas installer de client.

Vérifier depuis l'extérieur que l'origine HTTPS répond et que le certificat TLS est valide. `make get` affiche le Server ID (clé publique), les appareils et le stockage sans ouvrir d'appairage. Transmettre cette clé au client par un canal fiable. Installer le client depuis son dépôt GitHub, puis saisir son code dans `make pair` ; si cette commande est déjà ouverte, continuer dans ce terminal. Suivre le [guide client](install-client.md#appairer-et-approuver-un-appareil).
