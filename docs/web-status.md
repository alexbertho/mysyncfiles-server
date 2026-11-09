# Présence locale dans le navigateur

La page `/status` du serveur reconnaît une clé TPM approuvée qui répond à un challenge court. Elle affiche le nom enregistré de l’appareil, la version du client, l’activité du daemon et son dernier état de communication authentifiée. Elle ne donne accès à aucun fichier et ne crée aucun compte utilisateur.

La consultation et le téléchargement se font dans l’[explorateur Atlas](web-files.md), avec une autorisation locale `files.read` et une session distinctes. Activer le statut seul n’autorise pas la lecture des fichiers.

## Activer et consulter

Le client doit disposer de la fonctionnalité introduite en **0.3.7**. Vérifier `mysync --version` sur le PC du navigateur. Si nécessaire, lancer `mysync update` après publication de cette release par l'administrateur. Le redéploiement Docker du serveur ne distribue pas automatiquement un nouveau client. Un ancien client 0.3.6 ne reconnaît pas le champ `web_status_enabled`.

À partir de **0.3.8**, l’interface locale est **activée par défaut**. Les nouveaux profils enregistrent `"web_status_enabled": true`. L’installateur propose ce choix avant l’appairage ; répondre non pour la désactiver. Un profil existant sans ce champ utilise également `true`, tandis qu’un `false` enregistré reste respecté lors des mises à jour et des réinstallations.

Le client 0.3.8 permet de consulter et modifier le réglage sans éditer le JSON :

```sh
mysync web-status status
mysync web-status disable
mysync web-status enable
```

Ces commandes n’utilisent ni le TPM ni le réseau et ne modifient que le réglage du profil. Si une synchronisation verrouille le profil, attendre sa fin ou arrêter le daemon avant de changer le réglage. Relancer ensuite le daemon concerné. Pour un service utilisateur déjà installé et activé :

```sh
systemctl --user restart mysync
```

Ouvrir `https://sync.example.com/status`, en remplaçant le domaine d’exemple par l’origine du serveur configuré, puis cliquer sur **Vérifier**. Accepter la permission d’accès local si le navigateur la demande. Le bouton **Annuler** interrompt l’attente. Chaque actualisation est explicite ; il n’y a pas de sondage périodique du navigateur.

Avec le client 0.3.7, le réglage se fait encore dans le [profil client privé](configuration.md#client), en ajoutant `"web_status_enabled": true` puis en relançant le daemon. `mysync sync` et `mysync status` n’ouvrent aucune socket locale. La consultation web lit un petit état en mémoire ; elle ne parcourt pas le miroir et ne lance ni synchronisation ni commande système.

## Accès local et erreurs

Le daemon écoute uniquement sur `127.0.0.1:47831` et, si IPv6 est disponible, `[::1]:47831`. La page utilise IPv4, sans résolution de nom ni balayage de ports. Les sources CSP ne permettent pas de cibler une adresse IPv6 littérale ([CSP Level 3](https://www.w3.org/TR/CSP/#framework-directive-source-list)). Le repli IPv6 prévu initialement est donc omis du navigateur pour conserver une CSP limitée à l’adresse locale exacte ; la socket IPv6 reste disponible pour un appel direct respectant les mêmes contrôles. Une collision sur l’une des adresses disponibles désactive le pont entier et produit un message dans les logs ; la synchronisation continue. L’arrêt du daemon, une erreur terminale ou son redémarrage après mise à jour ferment le pont et les requêtes en cours.

Un seul profil peut être exposé sur ce port à la fois. Plusieurs profils ou utilisateurs Linux peuvent entrer en collision. Une connexion loopback ne permet pas d'identifier l'utilisateur Linux du navigateur.

Si le daemon affiche `web status bridge disabled: cannot bind IPv4 loopback`, la synchronisation continue mais ce processus n’expose pas le pont web. Les clients récents affichent aussi l’adresse et l’erreur système : `Address already in use` indique un port occupé ; `Permission denied` ou `Operation not permitted` indiquent une restriction locale. Vérifier sur le PC client :

```sh
ss -ltnp 'sport = :47831'
systemctl --user is-active mysync.service
```

Si `mysync.service` est actif et possède ce port pour le profil voulu, utiliser ce daemon et quitter celui lancé manuellement avec `Ctrl+C`. Pour travailler au premier plan, arrêter d’abord ce service avec `systemctl --user stop mysync.service`, puis relancer `mysync daemon`. Si le port appartient à un autre programme ou profil, identifier ce propriétaire avant de l’arrêter. Le pont utilise un port fixe ; il ne choisit pas un autre port automatiquement.

| Message | Interprétation |
| --- | --- |
| Machine reconnue | Le backend a confirmé une preuve TPM pour le challenge de cette session. |
| Réponse locale accessible, non vérifiée | Un service répond, mais le backend n’a pas reconnu d’appareil. |
| Permission refusée | Le navigateur a explicitement signalé le refus, lorsque son API le permet. |
| Client inaccessible ou accès bloqué | Daemon arrêté, interface désactivée, client absent ou politique navigateur/réseau. Ces causes ne sont pas toujours distinguables. |
| Vérification serveur indisponible | La consultation du backend n’a pas abouti. |
| Challenge ou authentification refusés | Session expirée, challenge invalide, appareil non approuvé ou révoqué, entre autres. |

La première sonde attend au plus 30 secondes pour laisser le temps d’autoriser l’accès local. Elle ne retourne ni version ni identité. Le challenge est créé ensuite. L’échange dispose de dix secondes, suivies d’une unique lecture du résultat de trois secondes au maximum : cette lecture peut récupérer une preuve déjà enregistrée même si la réponse locale s’est perdue.

Les politiques d’accès au réseau local, le mixed content loopback et les permissions varient selon les versions de Chromium et Firefox. La page détecte les API de permission disponibles sans en dépendre. Les en-têtes de préflight PNA anciens ne remplacent pas une permission LNA. Une validation sur les versions réellement utilisées reste nécessaire ; aucune compatibilité Safari n’est annoncée. Un navigateur exécuté sur une autre machine ne joint pas le loopback du client Linux.

## Protocole et limites

1. Le backend crée une session navigateur anonyme de cinq minutes. Son cookie `__Host-mysync-status` est `Secure`, `HttpOnly`, `SameSite=Strict`, avec `Path=/`. Seul son hash est conservé en base, avec une liaison opaque distincte.
2. Le navigateur demande un ticket de 60 secondes, signé par la clé Ed25519 du serveur sous le séparateur `mysync/web-status-challenge/v1`. Le ticket lie le challenge, la session, l’origine, l’audience, les dates et le scope `status.read`.
3. Le daemon contrôle l’origine, le `Host`, la signature avec sa clé serveur épinglée, les dates et le rejeu avant toute opération TPM. La requête exige les en-têtes `X-MySync-Bridge` et `X-MySync-Challenge`. Aucun jeton machine n’est transmis au JavaScript.
4. Le daemon envoie directement le ticket, son identifiant aléatoire d’instance et le statut au backend, avec la preuve TPM HTTP existante. La destination est fixe : `/v1/web/status/proofs`. Le backend résout l’appairage en appareil logique, revérifie approbation et révocation et consomme le challenge dans une transaction SQLite.
5. Le daemon vérifie la réponse signée du serveur. La page lit ensuite le résultat auprès du backend avec son cookie. Un faux service local ne peut pas produire une identité reconnue en renvoyant simplement du JSON.

Chaque challenge est indépendant, y compris entre onglets. Une actualisation d’une présence encore valide attend le même `device_id`, choisi par le backend à partir du résultat précédent. La présence expire au plus deux minutes après vérification, sans dépasser la session. La révocation invalide aussi les lectures ultérieures. Les challenges consommés restent inutilisables après redémarrage du serveur.

| Limite | Valeur |
| --- | --- |
| Ticket | 2 Kio |
| En-têtes HTTP locaux | 8 Kio, reçus en cinq secondes maximum |
| Corps de preuve et réponses JSON | 4 Kio |
| Connexions locales simultanées | 8, sans connexion persistante |
| Preuves locales | 1 en cours, 6 tentatives par minute |
| Challenges par session | 4 en attente, 12 créations par minute, 32 lignes conservées (les anciens challenges de fichiers expirés et non référencés sont purgés) |
| Sessions navigateur actives | 1 024 |

La file du signataire TPM reste bornée et ignore les demandes annulées avant leur traitement. Une opération TPM déjà commencée peut finir après l’annulation HTTP. Tous les résultats sont `no-store`. Les tickets passent dans des en-têtes ou des corps, jamais dans les URL ou les messages de log. Le proxy doit conserver ces règles et ne pas journaliser les corps ou en-têtes d’authentification.

Seule l’origine exacte configurée est autorisée : ni origine absente ou `null`, ni wildcard CORS. Les URI absolues, chemins supplémentaires, corps GET et upgrades sont refusés. Le profil et les tickets utilisent la politique de transport existante : HTTPS, avec l’exception HTTP sur loopback pour les essais isolés. Cette exception ne permet pas HTTP sur le réseau et le cookie de la page reste toujours `Secure`.

La CSP limite les scripts et styles au site, les connexions au backend et à `127.0.0.1:47831` ; elle interdit l’intégration en iframe. Les libellés sont insérés comme texte. L’autorisation couvre toute l’origine, pas seulement `/status` : une XSS sur cette origine pourrait consulter ce statut. Un site ou JavaScript compromis reste hors du modèle de menace, même si la clé épinglée protège le daemon contre un intermédiaire qui altère les tickets ou réponses.

## Ce qui est attesté

Le TPM prouve qu’une clé approuvée a répondu au challenge. La version, l’activité et les dates d’observation sont des déclarations du client authentifié ; aucune attestation du binaire ou de l’intégrité du système n’est effectuée. Un relais volontaire ou un tunnel peut transmettre le challenge à une autre machine. D’autres processus locaux ayant accès au profil et au TPM peuvent également utiliser la clé sur la machine légitime.

Le nom affiché vient du registre serveur, sans hostname, chemins, noms de fichiers, certificats EK, blobs TPM ou journaux bruts. `device_id` désigne l’appareil logique (`devices.id`) ; `identity.device` dans le profil reste l’identifiant d’appairage (`device_enrollments.id`). Une mise à jour conserve cette identité. Une perte du profil ou un remplacement du TPM exige un nouvel appairage ; une empreinte EK identique ne rattache pas automatiquement un nouvel appareil.

Les appareils approuvés synchronisent toujours **le même espace global de fichiers**. Ce POC n’ajoute ni propriétaire utilisateur ni espace par machine. Une future séparation devra migrer ensemble les entrées, manifestes, uploads, corbeilles, états locaux et autorisations ; la présence locale ne constitue pas à elle seule une autorisation d’accès à ces données.

## Validation développeur

`make test` couvre le protocole, les contrôles HTTP, les collisions et l’arrêt du pont, les sessions et la consommation concurrente, ainsi que l’échange réel avec deux `swtpm`. Les tests d’origine vérifient le refus des statuts et accusés de réception altérés par un proxy. La CI exécute aussi les tests TPM et de présence sur Debian 13 et Arch Linux.

La suite `tests/web_status_browser.cjs` utilise Playwright 1.60.0 installé séparément et un serveur loopback de test. Elle vérifie le rendu et le transport CORS dans Chromium 148 et Firefox 150 : reconnaissance, faux service local, réponse perdue, attente et annulation, refus de permission. Le backend de cette suite est simulé ; la preuve cryptographique est testée par la suite Rust. Le refus LNA est natif dans Chromium, simulé dans Firefox 150. La permission native de Firefox 153 et les dialogues interactifs ne sont pas couverts par cette validation automatisée.

Exécution avec Playwright et ses navigateurs déjà installés :

```sh
NODE_PATH=/chemin/vers/node_modules node tests/web_status_browser.cjs
```
