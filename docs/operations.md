# Déploiement et publication

Le [guide d'installation serveur](install-server.md) couvre la préparation de `deploy/.env`, des volumes et du proxy HTTPS. Cette page décrit les opérations qui suivent le premier démarrage. Les chemins et noms ci-dessous sont des exemples à adapter. Dans le dépôt source, le domaine est aussi un exemple ; le site publié utilise l'origine configurée par l'administrateur. Les secrets restent hors du dépôt et des fichiers servis publiquement.

## Compiler

Le dépôt serveur produit uniquement `mysync-server`. `cargo build --locked --release` nécessite Rust, OpenSSL et pkg-config, sans pilote TPM. L’image serveur ajoute `tpm2_makecredential` pour l’appairage, sans accès matériel. Le client se construit avec `make build` depuis [mysyncfiles-client](https://github.com/alexbertho/mysyncfiles-client), avec les bibliothèques TPM de Debian 13 ou Arch Linux.

## Publier un client signé

La signature et la distribution du client sont gérées dans le dépôt client : consulter son README et `docs/releases.md`. Les assets GitHub sont `latest-linux-x86_64.signed.json`, `latest-linux-aarch64.signed.json` et les binaires nommés dans les manifestes signés. La clé privée reste hors des dépôts et des assets publics. Le client contrôle signature, taille et SHA-256 avant remplacement, conserve le verrou d’installation et refuse les versions plus anciennes.

Les téléchargements de releases peuvent suivre au plus cinq redirections HTTPS, nécessaires pour les assets GitHub ; toute redirection HTTP est refusée. Les échanges avec un serveur de synchronisation continuent de refuser les redirections. L’installateur demande séparément l’URL de ce serveur. Le serveur ne sert plus `/install.sh` ni `/v1/updates/`.

La version 0.4 exige une mise à jour coordonnée. La séparation des sources ne publie pas une release signée et ne remplace aucun binaire installé. Conserver les profils, états et clés TPM existants ; sauvegarder la base avant toute intervention de production.

## Consulter l'instance

Depuis le dépôt serveur, `make get` affiche le nom, le **Server ID (clé publique)** à transmettre au client, l'origine publique, les nombres d'appareils approuvés/révoqués et d'invitations en attente, ainsi que les fichiers et le stockage. Cette commande lit l'instance existante sans créer d'invitation, purger des données ni initialiser une nouvelle base. Elle fonctionne sans terminal interactif et sans démarrer le service serveur.

MySyncFiles authentifie des appareils TPM et ne possède pas de comptes utilisateurs distincts : le nombre d'appareils approuvés n'est pas un décompte de personnes. Les tailles des fichiers, de la corbeille (y compris les éléments expirés encore présents) et des transferts reçus sont des octets logiques. La capacité et l'espace disponible concernent tout le système de fichiers du dossier de données, et non un quota propre à l'instance ; les fichiers SQLite et leurs journaux ne sont pas inclus dans les tailles logiques.

Hors Docker : `mysync-server info --data-dir DOSSIER`. Pour une sortie structurée :

```sh
docker compose --env-file deploy/.env -f deploy/compose.yaml run --rm --no-deps -T \
  server info --data-dir /data --json
```

Le Server ID correspond exactement à la valeur de `mysync-server server-key` ; aucune nouvelle identité n'est créée.

## Administrer les appareils

Le parcours recommandé est `make pair` : l'administrateur saisit le code affiché sur le client, attend la preuve TPM et confirme l'empreinte complète. La [procédure client](install-client.md#appairer-et-approuver-un-appareil) donne les commandes. Les sous-commandes `device` sont locales au serveur, jamais des routes HTTP d'administration. Le code enregistré expire après 15 minutes s'il n'est pas utilisé ; l'appairage en attente peut être annulé avec `device cancel --id ID --data-dir /data`. Le parcours manuel par invitation reste disponible.

Pour un appareil perdu ou compromis, exécuter `device revoke --name NOM --data-dir /data` dans le conteneur. Les nouvelles requêtes sont refusées ; une requête déjà autorisée peut terminer son traitement. Voir la [révocation et récupération](device-auth.md#revocation-et-recuperation) avant d'appairer un remplacement.

## Sauvegardes et maintenance

La base privée contient aussi la clé Ed25519 d'authenticité des réponses. `mysync-server server-key --data-dir DOSSIER` affiche sa partie publique, à transmettre aux clients par un canal fiable. Conserver cette clé avec les sauvegardes SQLite ; sa perte ou sa rotation impose de mettre à jour explicitement la clé épinglée de chaque client. La [migration des profils existants](device-auth.md#authenticite-des-reponses-et-migration) ne réinitialise ni les appareils TPM ni les fichiers.

L'état client est publié atomiquement une fois par passe modifiée, avec sérialisation tamponnée et synchronisation du fichier et du dossier parent. Un petit journal privé `config.state.journal` conserve durablement les mutations terminées entre deux publications. Il est rejoué au redémarrage ; ne pas le supprimer lors d'une récupération ou le séparer de `config.state.json` dans une sauvegarde. Une passe sans changement ne réécrit pas l'état.

Sauvegarder de façon cohérente le répertoire de données privé, qui contient la base SQLite et les blobs, ainsi que les éléments de configuration nécessaires à la restauration. Éviter une copie brute de SQLite pendant les écritures : arrêter le serveur le temps d'une copie des fichiers, ou utiliser une méthode de sauvegarde SQLite cohérente. Tester régulièrement la restauration sur un hôte isolé. Conserver les sauvegardes et la clé privée hors du dépôt et du répertoire de releases. MySyncFiles ne remplace pas ces sauvegardes : les écrasements ordinaires n'ont pas d'historique restaurable.

## Tests et déploiement

`make test` vérifie le formatage, les tests du serveur et du paquet commun, le script d’installation serveur et la documentation. Il ne compile pas le client et ne requiert ni pilote TPM ni `swtpm`. Les tests navigateur restent une étape distincte de la CI.

`make test-integration` assemble le serveur et une révision précise du dépôt client dans `integration/`, puis vérifie appairage TPM, transferts, refus, conflits, révocation et pont web. Les bibliothèques TPM manquantes sont fournies par `deploy/Dockerfile.tpm-dev`. Ces contrôles et les vérifications Debian 13/Arch restent requis avant publication. Pour travailler sur des changements coordonnés non commités, utiliser `MYSYNC_INTEGRATION_WORKTREE=1 make test-integration` avec les deux dépôts voisins.

`make deploy` lance les contrôles, valide `deploy/.env`, reconstruit l'image, génère la documentation avec l'origine configurée, recrée le service serveur et copie `site/` vers `/var/www/mysyncfiles/docs/` (ou `MYSYNC_DOCS_DIR`). Il faut Docker Compose, Docker Buildx, `flock`, Rust, Python 3, `rsync` et `sudo` sur l'hôte de déploiement. Cette commande ne publie pas de binaire client signé. `make clean` supprime seulement `target/` et `site/` ; les données privées, releases et fichiers déjà déployés restent en place.

`make logs`, `make stop` et `make start` pilotent le serveur sans supprimer les volumes. Les commandes directes `docker compose -f deploy/compose.yaml ...` restent utilisables. Ne pas démarrer deux serveurs sur la même base.

L'appartenance au groupe `docker` accorde des privilèges élevés sur l'hôte. Réserver les commandes Compose aux administrateurs autorisés.

La documentation se prévisualise indépendamment avec `make docs` sur `http://127.0.0.1:8000`, s'arrête avec `make docs-stop` et se valide avec `make docs-check`. Ce service local n'expose ni les données du serveur ni `deploy/.env`.

## Modifier l’interface web à chaud

L’interface native est dans `web/` : `index.html` pour la page, `status.css` pour les styles, `atlas.js` et `status.js` pour les interactions, avec les images et icônes à côté. Ces fichiers sont indépendants du binaire Rust et ne nécessitent ni npm ni compilation.

Docker Compose monte le dossier `web/` du dépôt dans `/web` en lecture seule. Après une modification, actualiser le navigateur : le serveur relit les fichiers à chaque requête et envoie `Cache-Control: no-store`. Une édition HTML/CSS/JavaScript ne nécessite ni `make install`, ni `make deploy`, ni redémarrage. Le montage porte sur le dossier entier, ce qui permet aussi les remplacements atomiques de fichiers par un éditeur.

Pour passer d’un ancien serveur avec interface embarquée à ce fonctionnement, une première reconstruction de l’image et une recréation du conteneur sont nécessaires, par la procédure de déploiement habituelle. Les retouches suivantes se font directement dans `web/`. Une image utilisée sans Compose contient également une copie de ces fichiers dans `/web` ; monter un dossier externe pour pouvoir les modifier à chaud.

Hors Docker, `mysync-server serve --web-dir /chemin/vers/web` indique le dossier public ; sa valeur par défaut est `web`, relative au répertoire de lancement. Conserver les autres arguments habituels, notamment `--data-dir`. Distribuer ce dossier avec le serveur lors d’une installation binaire.

Les routes `/`, `/index.html`, `/files`, `/editor` et `/status` servent le même HTML. Seuls les fichiers de l’interface explicitement exposés sont accessibles, sans parcours de répertoire. Les lectures refusent les liens symboliques et les fichiers de plus de 1 Mio. Les clés, profils et données synchronisées restent dans leurs répertoires privés. Un fichier web absent ou invalide produit une erreur `503` ; le remplacer rétablit la page sans redémarrage.

Le moteur de l’éditeur est livré dans `web/editor.js`, avec ses sources dans
`web/editor-src/` et les licences tierces dans `web/editor.LICENSE`. Après une
modification de ces sources, utiliser `make editor-build` (Node.js 20 ou plus
récent et npm). `make editor-check` vérifie que le bundle correspond aux sources
et aux dépendances verrouillées dans `web/package-lock.json`. Le serveur ne
nécessite pas Node.js et aucun script n’est téléchargé depuis un CDN. Les styles
de CodeMirror sont isolés dans un ShadowRoot ; la politique CSP conserve
`script-src 'self'` et `style-src 'self'`, sans exception pour du code inline.

## Mesurer les performances

`make benchmark` construit des binaires release et mesure de vrais processus
`mysync` face à un serveur local isolé, avec appairage et signatures via `swtpm`.
Les profils, clés et fichiers de test sont temporaires. Cette cible ne contacte
pas le serveur configuré dans `deploy/.env`. Elle utilise le même environnement
TPM que `make test-integration` ; Python 3 et Linux sont nécessaires.

```sh
make benchmark > benchmark.jsonl
make benchmark MYSYNC_BENCH_ARGS='--suite metadata --repetitions 5 --work-dir target' > metadata.jsonl
```

Les suites disponibles sont `metadata`, `transfer`, `overwrite`, `daemon`, `concurrent` et
`all`. Elles couvrent 100 et 10 000 fichiers de 4 Kio, les transferts de 100 et
1 000 petits fichiers, trois fichiers de 64 Mio, un miroir de 512 Mio, les
conflits, les remplacements ordinaires et 35 secondes de daemon au repos. `--delay-ms 40` ajoute 40 ms à chaque
réponse HTTP pour étudier le coût des allers-retours. `--binary CHEMIN` permet
de mesurer un autre client face au même serveur de benchmark.

Chaque mesure de commande contient le temps total, le CPU utilisateur/système, le pic
RSS du client, les blocs de 512 octets lus/écrits (`getrusage`), les requêtes HTTP
et les étapes de `status`/`sync`. Les compteurs d'I/O logiques dans `/proc` sont
échantillonnés toutes les 2 ms et peuvent manquer les toutes dernières opérations.
`scan` comprend parcours, métadonnées, lectures et SHA-256 ; `apply` comprend les
transferts et le journal durable. Certaines étapes s'exécutent simultanément :
leurs durées ne doivent pas être additionnées. Les timings ne sont activés que
par `MYSYNC_BENCH_TIMINGS=1` et n'incluent ni chemins ni contenus privés.
Les compteurs `harness_io_*` incluent le serveur de test et ses processus enfants
terminés ; ils ne permettent pas d'isoler les I/O du serveur.

Le serveur traite les opérations bloquantes avec huit tâches au maximum et
conserve sa limite de huit corps de requête signés en mémoire. Une requête
authentifiée peut attendre jusqu'à 250 ms qu'une place se libère avant de recevoir
HTTP 429 ; cette attente ne lit pas son corps et ne garde pas le verrou SQLite.

Comparer les médianes de plusieurs répétitions, avec le même matériel, quota
CPU, filesystem et état de cache, sans compiler pendant les mesures. Les scans
sont normalement servis par le cache du noyau : zéro bloc physique lu ne signifie
pas zéro lecture logique. Le serveur et les TPM simulés partagent le quota CPU
du benchmark ; ce test sur loopback ne mesure pas le TLS ni un TPM matériel.
Les scénarios de concurrence indiquent aussi les latences p50/p95 et le retard
maximal d'un timer Tokio. Vérifier `returncode` et les compteurs de fichiers avant
de comparer un ancien client : les versions qui reprennent après le curseur
`next` peuvent omettre une entrée à chaque page du manifeste.

## Publier la documentation

La prévisualisation MkDocs est réservée au poste local. Pour servir la documentation sur l'origine HTTPS du serveur à `/docs/`, construire des fichiers statiques, puis les faire servir par le proxy existant. Cette opération ne change ni l'API, ni l'origine configurée pour les clients TPM.

Depuis la racine du dépôt, générer le site après `device auth-configure`. `make docs-build` lit l'origine HTTPS enregistrée par l'administrateur dans la base serveur. Elle sert aux exemples d’origine serveur, aux liens canoniques et au sitemap ; l’URL de l’installateur reste celle du dépôt GitHub client ; elle n'est pas enregistrée dans le dépôt public :

```sh
make docs-build
```

`site/` est généré localement et ignoré par Git. Sur l'hôte du proxy, installer les fichiers dans le répertoire réservé à la documentation :

```sh
sudo install -d -m 0755 /var/www/mysyncfiles/docs
sudo rsync -a --delete site/ /var/www/mysyncfiles/docs/
```

Dans le **bloc HTTPS** Nginx de l'origine publique, placer les deux locations `/docs` et `/docs/` du modèle `deploy/nginx-sync.conf` avant la location générale `/`. Le répertoire `/var/www/mysyncfiles/docs/` doit rester distinct du stockage serveur et des releases. Vérifier puis recharger Nginx :

```sh
sudo nginx -t
sudo systemctl reload nginx
curl -fsSI https://sync.example.org/docs/
```

`/docs` redirige vers `/docs/` pour que les liens relatifs fonctionnent. Les autres chemins continuent vers le serveur MySyncFiles, avec leurs règles de cache et d'authentification actuelles. Pour mettre les pages à jour sans redémarrer le serveur, reconstruire avec `make docs-build` puis recopier `site/`. `make deploy` effectue ces opérations après les tests et la reconstruction du serveur. Ne pas exposer `site/` depuis le répertoire de données privé du serveur.
