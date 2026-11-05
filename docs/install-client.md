# Installer un client

Le client fonctionne sur Linux x86-64 ou AArch64 avec un TPM 2.0 accessible et un certificat EK constructeur correspondant. Debian 13 et Arch Linux/dérivées sont testés. Le serveur doit avoir son origine HTTPS et sa confiance EK configurées. La [release signée](operations.md#publier-un-client-signe) pour l’architecture du client provient du dépôt client.

Sauvegarder les fichiers importants avant la première synchronisation. Choisir un dossier miroir local distinct de la configuration privée du client.

## Installer le binaire signé

Dans la documentation source, remplacer le domaine d'exemple par l'origine HTTPS du serveur. La documentation publiée par `make docs-build` ou `make deploy` utilise automatiquement l'origine configurée par l'administrateur. Dans un terminal :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://raw.githubusercontent.com/alexbertho/mysyncfiles-client/main/deploy/install.sh | sh
```

Pour examiner le script avant sa première exécution, le télécharger dans un fichier, le lire, puis lancer `sh install.sh`. Le script utilise `/dev/tty` pour les questions interactives : l'appairage fonctionne aussi lorsque le script est transmis à `sh` par un pipe.

Le script propose les paquets manquants sur Debian/Arch avant tout `sudo`, vérifie la signature de la release et le hash du binaire, puis contrôle l'accès au TPM. Si `/dev/tpmrm0` est accessible au groupe `tss` mais pas à l'utilisateur courant, il propose de l'ajouter à ce groupe avec `sudo`. Il s'arrête ensuite : il faut fermer la session et se reconnecter (ou redémarrer), puis relancer l'installation pour que le nouveau groupe soit actif. Sans terminal, il affiche la commande à lancer manuellement. Dans un terminal, il demande l’URL HTTPS du serveur et le dossier miroir, affiche un code temporaire et attend l'administrateur. Si un ancien code d'appairage enregistré localement a expiré ou a été annulé, la reprise en crée un nouveau dans ce même lancement. Il lance la première synchronisation puis le service utilisateur seulement si l'appairage réussit et qu'aucun conflit ne reste dans `.mysync-conflicts/`. Une unité systemd existante différente est laissée intacte et n'est pas démarrée automatiquement. Sans terminal, il installe le binaire et l'unité sans appairer ni démarrer le service. Si un binaire existant diffère de la release signée, l'installateur refuse les versions plus récentes et demande confirmation avant de sauvegarder puis remplacer une version identique ou plus ancienne. Sans terminal, il demande de déplacer manuellement l'ancien binaire. L'examen du script et la confiance dans l'origine HTTPS restent importants : la signature du binaire ne protège pas un script distant compromis.

Avec `MYSYNC_PROFILE=default`, si un ancien profil contient un jeton `token`, l'installateur interactif propose de conserver ce profil et son état de révisions dans un dossier privé `legacy-profile.*` sous la configuration du client, puis reprend l'appairage TPM. Le dossier synchronisé reste à sa place ; sauvegarder séparément ses fichiers importants avant la première synchronisation et examiner les éventuels conflits. Sans terminal, le script s'arrête avec une explication. Un profil qui contient aussi une identité TPM doit être examiné manuellement : l'installateur ne l'archive pas automatiquement. Le jeton ancien n'est jamais accepté comme identité par le nouveau client.

Avec un client signé **0.3.8 ou ultérieur**, l’installateur demande aussi `Enable browser status on this PC? [Y/n]` avant l’appairage. Entrée active la [présence locale sur `/status`](web-status.md) ; répondre `n` la désactive. Une préférence déjà enregistrée devient le choix proposé, même après un appairage interrompu. Pour fixer ce choix sans question :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://raw.githubusercontent.com/alexbertho/mysyncfiles-client/main/deploy/install.sh | MYSYNC_WEB_STATUS=false sh
```

`MYSYNC_WEB_STATUS` accepte `true` ou `false`. Sans terminal, le script affiche la commande `setup` à lancer avec ce choix, sans appairer ni démarrer le service. Une ancienne release dépourvue de ce réglage reste installable sans cette variable ; un choix explicite nécessite une release 0.3.8 ou ultérieure. Après l’installation, utiliser `mysync web-status enable` ou `disable`, puis relancer le daemon. Une réinstallation réussie redémarre le service pour appliquer le binaire et le réglage.

Si le certificat EK constructeur manque dans les index NV du TPM, fournir son fichier DER obtenu auprès du fabricant :

```sh
curl -fsS --proto '=https' --max-redirs 0 https://raw.githubusercontent.com/alexbertho/mysyncfiles-client/main/deploy/install.sh | MYSYNC_EK_CERT=/chemin/prive/ek.der sh
```

L'installateur transmet le même certificat à `mysync setup`. Pour Intel PTT, le client lit automatiquement les intermédiaires présents dans le TPM et complète leur chaîne auprès du dépôt HTTPS de certificats Intel ; aucune étape manuelle n'est nécessaire si le serveur fait confiance à la racine Intel correspondante. Pour les autres intermédiaires constructeur, définir `MYSYNC_EK_CHAIN=/chemin/intermediaires.pem` lors de l'installation. Voir la [procédure et ses limites](device-auth.md#certificat-ek-absent-du-tpm). Ne pas remplacer le certificat constructeur par un certificat auto-signé.

## Appairer et approuver un appareil

Le client demande d'abord le Server ID (la clé publique du serveur). `make get` l'affiche sur le terminal administrateur sans ouvrir d'appairage : la transmettre directement par un canal fiable et la saisir sur le client. Cette clé protège les fichiers contre la falsification des réponses par un proxy TLS. Pour éviter la saisie, utiliser `mysync setup --server-public-key CLE_HEX ...` ou transmettre `MYSYNC_SERVER_PUBLIC_KEY=CLE_HEX` à l'installateur. Pour les profils déjà activés, suivre la [migration](device-auth.md#authenticite-des-reponses-et-migration).

Le client affiche un code à usage unique, puis attend. Sur l'hôte serveur, depuis le dépôt et avec `deploy/.env` configuré :

```sh
make pair
```

Si `make pair` est déjà ouvert pour lire la clé, continuer dans ce terminal. Saisir le nom de l'appareil et le code affiché sur le client, puis garder la commande ouverte. Après vérification du certificat EK et de la preuve TPM, comparer **l'empreinte complète** affichée par les deux commandes, par un canal fiable, puis confirmer sur le serveur. Le code seul ne donne pas accès aux fichiers. Il est enregistré sous forme de hash et expire au bout de 15 minutes s'il n'a pas été utilisé. La commande serveur et le client peuvent être relancés avec le même nom et le même code pour reprendre une demande en cours ; une demande expirée ou annulée nécessite un nouveau code. Un nouveau code pour un nom réservé propose de remplacer l'invitation en attente après confirmation, sans remplacer un appareil approuvé. Le client attend au plus 30 minutes par exécution.

Si l'installateur a été lancé sans terminal, démarrer l'appairage sur le client avec :

```sh
~/.local/bin/mysync setup --server https://sync.example.org --dir "$HOME/Sync"
```

Ajouter `--ek-cert /chemin/ek.der` et `--ek-chain /chemin/intermediaires.pem` si nécessaire. Après la première synchronisation, examiner les éventuels fichiers dans `.mysync-conflicts/` avant d'activer le service. Si `mysync setup` a réussi sans conflit hors de l'installateur, démarrer le service avec `systemctl --user enable --now mysync.service`. Pour un démarrage sans session ouverte : `sudo loginctl enable-linger "$(id -un)"`.

Avec le client 0.3.8, ajouter `--web-status false` à `setup` pour désactiver la présence navigateur dès l’appairage. Sans cette option, les nouveaux profils l’activent et une reprise conserve le choix précédent.

## Parcours manuel avec invitation

Sur le serveur, l'administrateur crée une invitation distincte et la transmet par un canal confidentiel. Le chemin privé ci-dessous est un exemple ; il doit être accessible en écriture à l'UID/GID du conteneur :

```sh
install -d -m 0700 "$HOME/.local/share/mysync-keys"
docker compose -f deploy/compose.yaml run --rm \
  -v "$HOME/.local/share/mysync-keys:/keys" \
  server device invite --data-dir /data --name nouvel-appareil \
  --output /keys/nouvel-appareil.key
```

Sur le client, après réception du fichier d'invitation :

```sh
~/.local/bin/mysync enroll --server https://sync.example.org \
  --server-public-key CLE_HEX --dir "$HOME/Sync" --invitation-stdin < /chemin/prive/invitation
```

Ajouter `--ek-cert /chemin/prive/ek.der` si le certificat n'est pas stocké dans le TPM, et `--ek-chain` si des intermédiaires constructeur vérifiés sont nécessaires. Le client affiche un identifiant et une empreinte. L'administrateur compare l'empreinte reçue **directement du client** à celle affichée par le serveur, par un canal fiable :

```sh
docker compose -f deploy/compose.yaml run --rm \
  server device pending --data-dir /data
docker compose -f deploy/compose.yaml run --rm \
  server device approve --data-dir /data \
  --id ID_APPARIAGE --fingerprint EMPREINTE_CLIENT
```

L'invitation seule ne donne pas accès aux fichiers. Les détails et la [révocation](device-auth.md#revocation-et-recuperation) sont dans le guide TPM.

## Activer la synchronisation manuelle

Après approbation, sur le client :

```sh
~/.local/bin/mysync enroll-activate
systemctl --user enable --now mysync.service
sudo loginctl enable-linger "$(id -un)"
~/.local/bin/mysync status
```

`enroll-activate` réalise la première synchronisation ; vérifier les fichiers et les éventuels conflits avant d'activer le service. Le *linger* permet au service utilisateur de démarrer sans session ouverte. Le script d'installation ne démarre jamais ce service avant l'appairage. Pour suivre son activité : `journalctl --user -u mysync.service -f`.

Pour un client construit depuis les sources, suivre plutôt l'[installation depuis les sources](https://github.com/alexbertho/mysyncfiles-client#développer). Pour une erreur, consulter le [dépannage](troubleshooting.md).

## Plusieurs serveurs

```sh
mysync --profile maison setup --server https://sync.example.org --dir "$HOME/Sync/maison"
mysync --profile travail setup --server https://work.example.org --dir "$HOME/Sync/travail"
mysync profiles
mysync --profile maison status
mysync daemon --all
```

La clé publique et l’approbation sont requises pour chaque serveur. Les profils ne partagent ni leurs révisions, ni leur clé de session, ni leurs consentements web. Choisir des dossiers distincts et non imbriqués. Le service installé utilise `daemon --all` ; redémarrer ce service après l’ajout d’un profil pour charger la nouvelle liste.

L’installateur choisit un nom local d’après l’hôte de l’URL ; `MYSYNC_PROFILE=maison` permet de le fixer. `MYSYNC_SERVER_URL=https://sync.example.org` fournit l’URL sans question, notamment sans terminal. Le nom annoncé par le serveur est seulement un libellé ; l’URL et la clé publique restent les références de confiance.

Le protocole 0.4 exige un client et un serveur mis à jour ensemble. Les appairages TPM approuvés et les états peuvent être conservés. Les releases viennent toujours de GitHub, quel que soit le serveur sélectionné. Une release 0.4 signée doit être publiée séparément avant de pouvoir l’installer automatiquement.
