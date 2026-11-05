# Dépannage

Commencer par vérifier le service concerné et conserver les messages d'erreur exacts :

```sh
make logs
~/.local/bin/mysync status
systemctl --user status mysync.service
journalctl --user -u mysync.service -f
```

`make logs` se lance sur l'hôte serveur depuis le dépôt ; les autres commandes se lancent sur le client. Ne pas publier les codes d'appairage, invitations, configurations privées, empreintes EK complètes ou journaux contenant des secrets.

| Symptôme | Vérification et suite |
| --- | --- |
| `make install` réclame `deploy/.env` | Copier et compléter `deploy/.env.example`, puis créer les dossiers avec les droits correspondant à l'UID/GID. Voir l'[installation serveur](install-server.md). |
| Le serveur ne peut pas ouvrir `/data` ou `/releases` | Contrôler les chemins absolus, leur existence et leurs permissions dans `deploy/.env`. Voir la [configuration](configuration.md). |
| `/install.sh` ou `/v1/updates/` répond 404 | Utiliser l’installateur du dépôt client ; les releases ne sont plus distribuées par le serveur. |
| L'installateur ne trouve pas de release | Publier une release signée pour l'architecture du client ; le serveur ne la fabrique pas au démarrage. Voir la [publication](operations.md#publier-un-client-signe). |
| `mysync update` ne change pas la version après un déploiement serveur | Comparer la version installée à la dernière release signée publiée. Une reconstruction Docker ne publie aucun client. Augmenter la version du paquet, construire et tester le binaire, puis le publier avec la clé de release. Voir la [publication](operations.md#publier-un-client-signe). |
| La page `/status` indique « Client inaccessible » | Vérifier un client 0.3.7 ou ultérieur sur le PC du navigateur, `web_status_enabled: true` dans son profil et un daemon relancé après la mise à jour. Si le port loopback 47831 n'écoute pas, vérifier ces prérequis avant les permissions du navigateur. Voir le [statut web](web-status.md). |
| `mysync daemon` affiche `web status bridge disabled: cannot bind IPv4 loopback` | La synchronisation continue. Vérifier le propriétaire du port avec `ss -ltnp 'sport = :47831'` et le service avec `systemctl --user is-active mysync.service`. Un service déjà actif ou un autre profil peut occuper le port. Voir les [erreurs du pont local](web-status.md#acces-local-et-erreurs). |
| `mysync setup` refuse un ancien champ `token` | Relancer l'installateur dans un terminal. Il propose de sauvegarder l'ancien profil et son état avant un nouvel appairage TPM ; sauvegarder aussi le miroir et examiner les conflits après la première synchronisation. Voir l'[installation client](install-client.md#installer-le-binaire-signe). |
| Le client refuse le TPM ou son certificat | Vérifier `/dev/tpmrm0`, les droits utilisateur, le certificat EK constructeur et, si nécessaire, `--ek-cert`. Voir les [prérequis TPM](device-auth.md#prerequis-client). |
| `/v1/enroll/start` répond 401 pendant l'installation | Consulter `make logs` sur le serveur. Si la chaîne EK est rejetée, vérifier les racines constructeur configurées et que la release client sait lire les intermédiaires du TPM. Pour Intel PTT, voir les [prérequis TPM](device-auth.md#prerequis-client). Ne pas approuver un appareil ni élargir la confiance avant d'avoir vérifié sa chaîne. |
| Le client demande le Server ID | Lancer `make get` sur le serveur et transmettre sa clé publique par un canal fiable. Un `make pair` déjà ouvert l'affiche aussi ; le conserver pour saisir le code client. |
| `mysync setup` attend le serveur | Saisir le code affiché sur le client dans le `make pair` déjà ouvert, ou lancer cette commande si nécessaire, et vérifier que l'origine HTTPS répond. Si le code a expiré ou a été annulé, relancer `mysync setup` pour en générer un nouveau. |
| `device already enrolled or an invitation is pending` sur un ancien serveur, ou invitation déjà en attente | Reprendre avec le même nom et le même code. Avec le serveur mis à jour, `make pair` propose de remplacer une invitation en attente après confirmation si le code a changé. Un appareil approuvé reste protégé : reprendre son profil existant ou choisir un autre nom pour un nouveau client. |
| `mysync setup` attend l'approbation | Dans `make pair`, comparer l'empreinte TPM complète avec celle du client, puis confirmer. En cas d'interruption, relancer `make pair` avec le même nom et le même code. |
| L'appairage manuel attend l'approbation | Comparer l'empreinte reçue du client avec `device pending`, approuver la même identité, puis lancer `mysync enroll-activate`. Voir le [parcours manuel](install-client.md#parcours-manuel-avec-invitation). |
| Le service reste arrêté après la première synchronisation | Examiner les fichiers de `.mysync-conflicts/` et les erreurs affichées, puis relancer `mysync setup` ; activer le service seulement après une vérification sans conflit. |
| Erreurs de preuve ou d'URL après mise en place du proxy | Vérifier l'origine HTTPS exacte, les horloges et la transmission intacte de la méthode, de l'URL, du corps et des en-têtes. Voir le [protocole](device-auth.md#protocole-des-requetes). |
| Des changements ne remontent pas immédiatement | Lancer `mysync sync` et examiner les conflits locaux ; si la surveillance échoue, le client interroge le miroir toutes les 15 secondes. Voir le [client](client.md). |

Après perte du TPM ou de la configuration, suivre la [révocation et la récupération](device-auth.md#revocation-et-recuperation). Sauvegarder le miroir avant un nouvel appairage ; ne pas effacer le TPM pour résoudre une erreur d'accès.

| Plusieurs serveurs configurés | Préciser `--profile NOM` pour une commande, ou `daemon --all` pour les synchroniser ensemble. |
| Erreur de protocole après migration | Mettre à jour client et serveur en version 0.4 ; aucun repli vers le protocole précédent. |
