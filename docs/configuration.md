# Configuration

## Serveur

Copier `deploy/.env.example` vers `deploy/.env`, puis renseigner les valeurs propres à l'hôte. Ce fichier est ignoré par Git.

| Variable | Rôle |
| --- | --- |
| `MYSYNC_UID`, `MYSYNC_GID` | Identité du processus serveur et propriétaire attendu des données. |
| `MYSYNC_DATA_DIR` | Chemin absolu du stockage privé : SQLite et fichiers. |

Créer le dossier privé avant `make start`. Les invitations et la base restent hors du dépôt. L'[installation serveur](install-server.md#preparer-le-stockage) donne un exemple complet.

Docker Compose monte aussi `web/` dans `/web`, en lecture seule, pour servir l’interface native. Hors Docker, `mysync-server serve --web-dir CHEMIN` permet de choisir ce dossier (par défaut `web`). Les fichiers sont relus à chaque requête ; voir les [modifications à chaud](operations.md#modifier-linterface-web-a-chaud).

La commande `device auth-configure` enregistre dans SQLite l'origine publique HTTPS exacte (`--public-url`) et les racines EK constructeur vérifiées (`--ek-roots`). Elles ne sont pas déduites des en-têtes du proxy et aucune racine de test n'est installée par défaut. La [procédure TPM](device-auth.md#configuration-du-serveur) donne la commande complète. Le proxy doit préserver le corps et les en-têtes d'authentification, sans mise en cache des routes protégées.

## Client

Toutes les commandes visant un serveur acceptent `--profile NOM` ; préciser ce nom dès que plusieurs serveurs sont enregistrés. `mysync profiles` affiche les connexions locales. Les dossiers doivent être distincts et non imbriqués, y compris pour les appairages en attente.

`web_files_enabled` est une autorisation distincte, désactivée par défaut, y compris pour les profils existants. `mysync web-files enable` autorise les nouveaux challenges `files.read` après redémarrage du daemon ; `disable` les refuse. Le pont `web_status_enabled` doit aussi être actif. Le statut seul ne permet pas de lire les fichiers. Voir [l’explorateur web Atlas](web-files.md) pour l’accès automatique lié au client local et la révocation.

`web_uploads_enabled` autorise séparément l’ajout de fichiers depuis Atlas. Il est désactivé par défaut et se règle avec `mysync web-files enable-upload` ou `disable-upload`, puis un redémarrage du daemon. Une preuve `files.write` exige aussi `web_files_enabled` ; autoriser la lecture seule n’autorise jamais l’envoi. L’envoi web refuse de remplacer les fichiers existants.

`web_edit_enabled` et `web_run_enabled` sont également désactivés par défaut.
Les commandes `mysync web-files enable-edit` et `enable-run` autorisent
respectivement l’édition de fichiers Python/C et l’exécution locale isolée.
Les commandes `disable-edit` et `disable-run` les désactivent. Le daemon doit
être relancé après modification du profil. Voir les
[autorisations et limites de l’éditeur](web-code-editor.md).

`web_status_enabled` est un booléen, `true` par défaut depuis la version 0.3.8, enregistré dans les nouveaux profils. Un ancien profil sans ce champ utilise `true` ; un `false` explicite reste conservé. À `true`, `mysync daemon` expose le pont de présence sur le port loopback 47831 pour la page `/status` du serveur. Utiliser `mysync web-status status`, `enable` ou `disable` pour consulter ou modifier ce réglage. L’installateur propose le choix et `mysync setup --web-status true|false` permet de le fixer pendant l’appairage. Un redémarrage du daemon est nécessaire après modification. Voir [le fonctionnement et les limites du statut web](web-status.md).

Le champ `server_public_key` contient la clé publique Ed25519 reçue directement de l'administrateur. `setup` et `enroll` acceptent `--server-public-key CLE_HEX`, ou la demandent dans un terminal. Un ancien profil sans cette clé refuse de synchroniser jusqu'à l'exécution de `mysync trust-server --public-key CLE_HEX` ; voir la [migration](device-auth.md#authenticite-des-reponses-et-migration). Cette clé est distincte de `update_public_key`, utilisée pour les releases.

`config.state.journal` accompagne `config.state.json` lorsqu'une passe comporte des mutations. Le journal permet de reprendre après interruption avant la publication du prochain état complet ; conserver les deux fichiers ensemble lors d'une sauvegarde du profil.

`mysync enroll --server URL --dir DOSSIER` crée la configuration privée du client après attestation TPM. Son chemin par défaut est `$XDG_CONFIG_HOME/mysync/config.json`, ou `$HOME/.config/mysync/config.json` si `XDG_CONFIG_HOME` n'est pas défini. L'option globale `--config CHEMIN` permet d'utiliser un autre fichier. Le fichier d'état et le fichier d'appairage en attente sont placés à côté, hors du miroir.

Le certificat EK externe éventuel est un fichier DER fourni explicitement à l'installateur (`MYSYNC_EK_CERT`) et à `mysync enroll --ek-cert`. Les certificats intermédiaires vérifiés peuvent être passés à `--ek-chain`. Ni l'un ni l'autre ne modifient automatiquement la confiance du serveur. Voir le [guide client](install-client.md) et le [guide TPM](device-auth.md#prerequis-client).

Le service utilisateur installé démarre `mysync daemon --all`. Les profils nommés vivent dans `mysync/profiles/NOM.json` ; l’ancien `config.json` est aussi pris en compte. Un profil passé avec `--config` hors de ces emplacements exige une unité spécifique. Chaque profil possède son identité TPM, son état et ses consentements. Le pont loopback unique sélectionne le profil par origine HTTPS exacte. Deux profils exposant le pont pour la même origine sont refusés.
