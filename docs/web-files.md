# Explorateur web Atlas

Ouvrir `https://sync.example.com/files` (ou la racine `/` du serveur) pour consulter l’espace synchronisé. Atlas permet de parcourir les dossiers, rechercher par nom ou chemin, consulter les propriétés et télécharger des fichiers. Avec des autorisations locales supplémentaires distinctes, il permet d’**ajouter des fichiers par glisser-déposer** et de **renommer ou supprimer des dossiers avec leur contenu**. L’envoi ne remplace aucun fichier existant ; la restauration reste disponible par le client Linux.

Le menu latéral se masque entièrement avec le bouton en haut à gauche. Sans préférence enregistrée, il est replié sur les écrans de 1100 pixels ou moins pour laisser la place aux fichiers. Le bouton lune/soleil en haut à droite change le thème. Ces deux préférences sont conservées dans le navigateur ; les noms et le contenu des fichiers ne sont pas enregistrés dans le stockage local de la page.

L’interface est constituée de fichiers HTML, CSS et JavaScript natifs dans `web/`, sans framework ni compilation frontend. Le serveur les lit à chaque requête. Avec Docker Compose, ce dossier est monté en lecture seule dans le conteneur : modifier `web/index.html`, `web/status.css` ou les scripts, puis actualiser le navigateur suffit. Voir [modifier l’interface à chaud](operations.md#modifier-linterface-web-a-chaud) pour la configuration et la mise en place initiale.

## Autoriser la lecture

Le PC Linux du navigateur doit disposer du client **0.3.10 ou ultérieur**, appairé et approuvé sur ce serveur. Le client 0.3.9 publié sait vérifier `/status`, mais ne prend pas en charge `files.read` ni `mysync web-files`. Le déploiement du serveur ne met pas à jour les clients : leur distribution passe toujours par une release signée publiée séparément.

L’[installation récente](install-client.md#installer-le-binaire-signe) propose d’autoriser toutes les capacités web, oui par défaut ; répondre non les désactive toutes. Les profils existants conservent leurs choix, et un profil sans consentement de lecture garde ce droit désactivé. La lecture reste réglable séparément de la présence locale :

```sh
mysync web-files status
mysync web-files enable
```

Si le daemon verrouille le profil, l’arrêter avec `systemctl --user stop mysync.service` avant de changer ce réglage, puis lancer `mysync restart`. Cette commande recharge systemd et redémarre le service de tous les profils. Sur un ancien client : `systemctl --user daemon-reload && systemctl --user restart mysync.service`. Pour un daemon lancé dans un terminal, Ctrl+C puis relancer sa commande avec les mêmes options. Le pont local doit aussi être actif (`mysync web-status status`, puis `mysync web-status enable` si nécessaire).

Atlas reconnaît automatiquement le client à l’ouverture. Accepter l’accès local si le navigateur le demande ; le bouton **Vérifier cet appareil** permet de réessayer si nécessaire. Le serveur confirme la preuve TPM et le scope `files.read`, puis la page renouvelle l’accès en arrière-plan : **aucune vérification manuelle toutes les 30 minutes**. Garder le client lancé et la lecture web autorisée. L’autorisation `status.read` ne suffit pas. Les conditions et limites du [pont loopback](web-status.md#acces-local-et-erreurs) restent applicables.

Cette fonction nécessite la mise à jour du serveur et de ses fichiers web. Elle réutilise le protocole des clients existants qui prennent en charge les scopes concernés ; aucune nouvelle commande de configuration cliente n’est nécessaire. Une permission d’accès local peut encore être demandée par le navigateur, notamment lors du premier accès.

Tous les appareils approuvés consultent le **même espace global de fichiers**. L’approbation ne crée ni compte utilisateur ni dossier privé par appareil. Le client local autorise l’origine configurée ; cette autorisation ne distingue pas les utilisateurs Linux ou les navigateurs exécutés sur ce PC.

## Parcourir et télécharger

Les dossiers sont déduits des chemins des fichiers vivants ; les dossiers vides et les entrées supprimées ne sont pas présentés. Un **clic simple sélectionne un dossier** ; un **double-clic l’ouvre**. Au clavier, **Entrée** ouvre le dossier et **Espace** le sélectionne. Le menu **…** propose également **Ouvrir**, adapté aux écrans tactiles. Cliquer sur le fil d’Ariane pour remonter. La recherche couvre tout l’espace, même lorsqu’elle est lancée depuis un sous-dossier. Les caractères `%` et `_` sont recherchés littéralement.

La colonne **Taille** affiche pour chaque dossier la somme des tailles de tous ses fichiers, sous-dossiers compris, hors fichiers supprimés. Il s’agit de la taille logique des fichiers, pas de l’espace disque physique occupé par le serveur. Le calcul utilise les métadonnées SQLite dans la requête de liste existante : aucun fichier n’est ouvert pour mesurer sa taille et aucune requête supplémentaire par dossier n’est nécessaire. Le parcours d’un sous-dossier utilise l’index des chemins pour limiter la lecture à son contenu.

La colonne **Dernière modification** affiche la date d’enregistrement de la version courante sur le serveur, dans le fuseau horaire du navigateur. Elle ne correspond pas nécessairement à la date de modification du fichier sur le PC. Pour un dossier, elle indique la date la plus récente parmi ses fichiers présents, sous-dossiers compris ; les fichiers supprimés sont exclus. Cette date est calculée avec la taille dans la même requête SQLite. Si le serveur ne fournit pas encore cette information, un tiret est affiché.

Chaque ligne de fichier propose un menu **…** : **Télécharger**, **Voir les détails**, **Copier le chemin**. Un clic sur son nom ouvre aussi le panneau latéral. Celui-ci affiche le nom et le chemin complets, la taille, la date avec les secondes et le fuseau horaire, la révision et l’empreinte SHA-256 complète. Les noms trop longs sont seulement tronqués dans la liste.

Un **double-clic sur un PDF** ouvre son URL directe dans un nouvel onglet, avec le lecteur PDF intégré du navigateur. Cette fonction nécessite une mise à jour du serveur pour ajouter la route de lecture PDF ; remplacer seulement le JavaScript ne suffit pas. Cette lecture est limitée à **256 Mio** et exige la même session de lecture autorisée ; le lien ne rend pas le fichier public. L’URL désigne la révision affichée : si elle change, actualiser la liste avant de rouvrir le PDF. Le serveur transmet le contenu progressivement et prend en charge les requêtes de plages d’octets du lecteur. Cette ouverture directe ne passe pas par la vérification SHA-256 JavaScript du téléchargement ; les préférences du navigateur peuvent aussi imposer l’enregistrement des PDF.

La ligne sélectionnée est repérée en bleu et reste liée au panneau de détails. Sur les écrans de 1100 pixels ou moins, le panneau se superpose à la liste ; **Échap**, le bouton de fermeture ou un clic dans la zone à côté du panneau ramène au fichier sélectionné. Sur téléphone, il occupe toute la largeur, avec les informations défilantes et le bouton **Télécharger** toujours accessible. Sous 480 pixels, la liste privilégie le nom et la taille ; la date du fichier reste consultable dans les détails. Les chemins longs du fil d’Ariane défilent horizontalement et restent navigables au clavier.

La liste affiche au plus **200 éléments par page**, dossiers en premier, dans l’ordre des chemins. Utiliser les boutons de pagination pour continuer. L’icône **Actualiser les fichiers**, près de la recherche, met à jour la page courante en conservant les détails ouverts si le fichier est encore présent ; les changements du serveur ne sont pas sondés en permanence. Les lignes restent affichées pendant une requête, puis les résultats et le chemin sont remplacés ensemble. Une erreur de connexion conserve la liste précédente et permet de réessayer la navigation demandée avec l’icône d’actualisation. Le navigateur masque les données affichées à l’expiration ou à la déconnexion, et revérifie l’autorisation avant de restaurer une page depuis son historique.

Le téléchargement utilise des blocs d’au plus **8 Mio**, liés à une révision précise. Si le fichier change ou est supprimé pendant le transfert, actualiser la liste et recommencer. Le navigateur compare l’empreinte SHA-256 du contenu reçu à celle des métadonnées avant de lancer l’enregistrement. Le message **Téléchargement lancé** confirme la remise au navigateur, pas l’écriture finale sur le disque.

Cette première version limite les téléchargements web à **256 Mio par fichier**, avec un seul transfert à la fois, afin de borner la mémoire utilisée pour l’assemblage et la vérification. Les fichiers plus volumineux restent accessibles par la synchronisation Linux. Le bouton **Annuler** interrompt la préparation du téléchargement.

## Ajouter des fichiers

Le consentement d’envoi autorise seulement la création de nouveaux fichiers. La gestion des dossiers décrite ci-dessous exige son propre consentement.

L’envoi nécessite le client **0.3.11 ou ultérieur** et un serveur incluant cette fonctionnalité. Le client 0.3.10 permet la lecture, mais ne connaît pas `enable-upload`. Les anciens serveurs restent consultables, mais le bouton d’ajout y est désactivé. La publication d’une release cliente signée et son installation sont distinctes d’une modification du code web.

L’autorisation d’envoi est incluse dans le choix global de l’installation. Sans ce choix, activer seulement la lecture ne l’accorde pas. Sur le PC du navigateur, arrêter le daemon s’il verrouille le profil, puis exécuter :

```sh
mysync web-files enable
mysync web-files enable-upload
mysync web-files status
```

Lancer ensuite `mysync restart` pour le service installé. `status` affiche les réglages de lecture, d’envoi et, sur les clients récents, de gestion des dossiers. Le pont local doit aussi être actif.

Ouvrir le dossier de destination puis déposer les fichiers sur sa liste, ou utiliser **Ajouter des fichiers**, également accessible au clavier et sur téléphone. La zone bleue affiche le chemin de destination ; **Échap** annule le dépôt avant son relâchement. Les résultats de recherche et la navigation en cours n’acceptent pas de dépôt. Un dépôt sur le menu ou hors de la liste n’ajoute rien et n’ouvre pas le fichier dans le navigateur.

Au premier envoi, une preuve TPM distincte `files.write` est demandée au client local et confirmée par le serveur. L’autorisation reste liée au même appareil, au même appairage et à la même session que la lecture. Son renouvellement automatique exige sa propre preuve `files.write` ; une preuve de lecture seule ne le prolonge pas. Les transferts déjà commencés conservent leur autorisation lors d’un renouvellement réussi.

La sélection accepte jusqu’à **50 fichiers**, de **256 Mio maximum chacun**. Les dossiers ne sont pas pris en charge. Les fichiers sont traités successivement : calcul SHA-256, transfert par blocs d’au plus **8 Mio**, vérification serveur et publication. Le contenu n’apparaît dans la liste qu’après publication. L’indication **Envoyé** exige une confirmation du serveur ; une confirmation perdue invite à actualiser avant de réessayer. Les appareils Linux synchroniseront les fichiers ajoutés lors de leur prochain passage.

Un nom déjà présent est refusé, y compris si le fichier apparaît pendant le transfert. Le fichier local et la version serveur restent conservés ; renommer le fichier local pour l’ajouter sous un autre nom. Les chemins dangereux et les collisions entre fichier et dossier sont aussi refusés.

Le suivi permet d’annuler les fichiers restant à envoyer. Les fichiers déjà confirmés restent sur le serveur. Une annulation pendant la confirmation peut arriver après la publication : vérifier la liste. Changer de dossier ne change pas la destination d’un envoi déjà commencé. Le serveur borne les sessions d’envoi en attente à quatre par session navigateur et seize par appareil, transferts du client Linux compris ; les temporaires abandonnés sont purgés après expiration de l’autorisation ou par le nettoyage des transferts.

Pour refuser les **nouvelles** autorisations d’envoi, utiliser `mysync web-files disable-upload`, puis relancer le client. `mysync web-files disable` refuse également les nouvelles preuves d’envoi. Les autorisations déjà accordées expirent avec la session ; la déconnexion ou la révocation de l’appareil invalide les prochaines opérations.

## Gérer les dossiers

Le menu **…** d’un dossier propose **Propriétés**, **Renommer** et **Supprimer**. Les propriétés indiquent son nom, son chemin, la taille totale, la dernière modification et le nombre de fichiers, sous-dossiers compris. Elles utilisent la session de lecture ; aucun consentement de gestion n’est nécessaire pour les consulter.

Renommer ou supprimer nécessite le client **0.3.12 ou ultérieur**, un serveur incluant ces routes et un consentement de gestion. Le choix global de l’installation inclut ce droit ; activer seulement l’envoi ne l’accorde pas. Pour le régler séparément :

```sh
mysync web-files enable
mysync web-files enable-manage
mysync web-files status
```

Arrêter le daemon avant de modifier un profil verrouillé, puis relancer le client ou son service déjà installé. La nouvelle préférence est `web_management_enabled`. Au premier changement, le navigateur demande une preuve TPM `files.manage`, liée à l’appareil, à l’appairage et à la session de lecture courants. Cette preuve ne prolonge pas la session. Pour refuser de nouvelles autorisations de gestion : `mysync web-files disable-manage`, puis relancer le client. Les clients anciens doivent être mis à jour par une release signée ; modifier l’interface ou déployer le serveur ne met pas à jour le client.

**Renommer** change le nom du dossier dans son parent, avec tous les sous-dossiers et fichiers. Le serveur refuse un nom déjà occupé par un fichier ou un dossier et ne fusionne pas les contenus. **Supprimer** demande une confirmation explicite, puis supprime récursivement le dossier de l’espace synchronisé. Les fichiers sont conservés **30 jours dans la corbeille serveur**, restaurable via le client Linux. Ces changements se propagent aux appareils ; les modifications locales concurrentes restent soumises aux règles de conflit habituelles.

Chaque opération est atomique et limitée à **10 000 fichiers**, sous-dossiers compris. Les propriétés restent consultables au-delà de cette limite. Le serveur vérifie les révisions de tout le contenu : si un fichier est ajouté, modifié ou supprimé depuis l’ouverture de la confirmation, fermer celle-ci, actualiser la liste et recommencer. Une réponse perdue n’est pas une confirmation d’échec : actualiser la liste avant de réessayer. Les dossiers vides ne sont toujours pas représentés.

## Éditer et exécuter du code

Les fichiers Python et C disposent aussi d’une action **Modifier le code** et
s’ouvrent par double-clic dans l’[éditeur dédié](web-code-editor.md). L’édition
et l’exécution sur ce PC nécessitent chacune une autorisation supplémentaire.
Ces fonctions exigent un serveur et un client intégrant l’éditeur ; une mise à
jour des seuls fichiers web ne suffit pas.

## Expiration et révocation

**Déconnexion** supprime la session sur le serveur, ses challenges et ses autorisations de lecture, d’envoi et de gestion des dossiers. Les autres onglets ouverts sur la même origine effacent aussi leur affichage lorsqu’ils reçoivent cette déconnexion. Une préférence locale empêche la reconnexion automatique, y compris après rechargement ; cliquer sur **Vérifier cet appareil** pour la réactiver. Cette préférence ne contient ni jeton ni données de fichiers. Annuler une vérification suspend également la reconnexion automatique.

L’accès ne présente plus de coupure périodique : cinq minutes avant la première échéance, Atlas refait les preuves locales nécessaires sans effacer la liste ni interrompre les transferts autorisés. Les onglets coordonnent ce renouvellement lorsque le navigateur prend en charge Web Locks. Consulter un dossier ne prolonge aucun droit à lui seul. Au retour d’un onglet après une veille, une autorisation expirée est revérifiée automatiquement.

Si le client est arrêté, si un consentement local est retiré ou si le réseau est indisponible, les droits concernés cessent de se renouveler. L’autorisation déjà accordée reste utilisable jusqu’à son échéance, **au maximum 30 minutes après sa dernière preuve** : l’arrêt du client ne constitue pas une révocation instantanée. Le navigateur masque les fichiers à cette échéance. Déconnexion et révocation serveur permettent d’invalider les prochaines requêtes immédiatement.

Les autorisations d’édition et d’exécution sont également supprimées. L’éditeur
conserve un éventuel brouillon non confirmé à l’écran pour permettre son
téléchargement ; il bloque alors la sauvegarde et le lancement.

```sh
mysync web-files disable
```

Après redémarrage du daemon, cette commande refuse les **nouvelles** preuves de lecture. Les sessions déjà accordées restent valables jusqu’à leur expiration ou leur déconnexion. La révocation administrative de l’appareil invalide immédiatement les prochaines requêtes de métadonnées, de blocs, de lecture PDF et de gestion des dossiers. Elle ne retire pas les fichiers déjà téléchargés, ni le contenu d’une réponse déjà autorisée. Un onglet resté immobile peut conserver son affichage jusqu’à sa prochaine requête ou l’expiration locale.

Les vues de vérification, de permission refusée et de session expirée n’affichent aucun nom de fichier. Si la permission locale est refusée, ouvrir les permissions du site dans la barre d’adresse du navigateur, autoriser l’accès au réseau local et réessayer. Si la lecture est désactivée dans le client, la page indique comment l’activer.

Si `/status` reconnaît l’appareil mais que `/files` affiche « Vérification locale refusée », vérifier que `mysync web-files status` existe dans le client installé. Un ancien client peut synchroniser et prouver sa présence tout en refusant les demandes de lecture web. Utiliser un client incluant Atlas, activer `mysync web-files enable`, puis relancer le service déjà installé. Si la commande existe et que la lecture est activée, vérifier que le daemon en cours a bien été relancé, qu’il utilise le même serveur et que l’horloge du PC est correcte. Le navigateur consulte toujours le serveur avant d’accorder l’accès, même si la réponse locale indique une erreur.

## Protocole et limites de confiance

La session utilise le cookie distinct `__Host-mysync-files`, `Secure`, `HttpOnly`, `SameSite=Strict`, avec `Path=/`. Seul son hash est enregistré sur le serveur. La phase anonyme expire après cinq minutes ; une preuve `files.read` valide prolonge l’autorisation jusqu’à 30 minutes après sa réception. Les réponses autorisées de session et de résultat de preuve rafraîchissent le cookie jusqu’à l’échéance courante augmentée de cinq minutes, sans prolonger les droits serveur. Une simple lecture de session, un cookie ou une réponse locale non confirmée par le serveur ne suffisent jamais à renouveler l’autorisation.

Les renouvellements sont liés au même appareil et au même appairage. Chaque scope supplémentaire conserve son échéance jusqu’à sa propre nouvelle preuve. Les identifiants des envois et exécutions encore autorisés sont conservés ; un changement d’instance du daemon renouvelle l’identité d’autorisation de l’exécution. Les sessions et challenges partagent les quotas bornés du [protocole de présence](web-status.md#protocole-et-limites). Dans une session de fichiers authentifiée, les anciens challenges expirés sont purgés, sauf ceux référencés par les autorisations, pour éviter une limite cumulative après plusieurs renouvellements. Les limites de création par minute et de challenges en attente restent applicables.

Le ticket signé lie le scope, l’origine, l’audience, la session, l’appareil attendu le cas échéant et les dates. Le client contrôle les consentements locaux avant de signer une preuve avec le TPM. Le serveur consomme le challenge une seule fois, puis contrôle l’appairage, l’approbation, la révocation et l’expiration à chaque lecture ou envoi de bloc, ainsi que dans la transaction qui publie un fichier. Les routes de lecture web n’autorisent aucune mutation ; les routes d’envoi exigent `files.write` et vérifient aussi la propriété du transfert par cette session. La gestion des dossiers exige le scope distinct `files.manage`, contrôlé dans la transaction atomique de renommage ou suppression. Les réponses sont `no-store`, les erreurs sont génériques et les libellés sont insérés comme texte.

Comme pour la page de statut, le navigateur doit recevoir un HTML et un JavaScript de confiance. Un site compromis ou un proxy capable de remplacer l’application web peut altérer son affichage ; la vérification SHA-256 dans cette application ne constitue pas une authentification indépendante du code servi. Le client Linux conserve sa vérification des réponses signées avec la clé serveur épinglée. Atlas n’est ni un chiffrement de bout en bout ni une sauvegarde : les fichiers sont en clair sur le serveur et les écrasements ordinaires n’ont pas d’historique restaurable.

## Validation développeur

`make test` valide les sessions, les scopes, les chemins, la pagination, les limites de blocs, la révocation et les consentements locaux, ainsi qu’un échange de lecture, d’envoi et de gestion des dossiers avec un TPM simulé. Les régressions d’envoi couvrent également les collisions concurrentes, les empreintes, les quotas, l’annulation et l’isolation des sessions. Les régressions des dossiers vérifient les collisions, les changements concurrents, la corbeille, les limites et le retour intégral à l’état précédent si une opération échoue. La suite navigateur utilise les mêmes outils isolés que la [suite de présence](web-status.md#validation-developpeur) :

```sh
NODE_PATH=/chemin/vers/node_modules node tests/web_files_browser.cjs
```

Elle couvre les thèmes, la navigation repliable, la sélection et l’ouverture des dossiers, leurs propriétés, le renommage, la suppression confirmée, les menus au clavier, les noms longs, la recherche, la pagination, les états d’accès, l’expiration, l’ouverture des PDF dans un nouvel onglet, les téléchargements et leur intégrité. Les envois couvrent le dépôt, le sélecteur de fichiers, les fichiers vides, les blocs, les refus d’autorisation, les accusés perdus, les doublons, l’annulation et le changement de dossier pendant l’envoi. Les contrôles de mise en page couvrent les largeurs de 320, 390, 760, 768, 1100, 1440 et 1920 pixels, les chemins profonds, la stabilité du chargement et le retour du focus après fermeture des détails. Définir `MYSYNC_SCREENSHOTS=/tmp/atlas-captures` pour conserver les captures. Le backend de cette suite est simulé ; l’autorité cryptographique est vérifiée par les tests Rust. Les icônes Phosphor sont distribuées avec leur licence MIT dans `web/atlas-icons.LICENSE` ; la marque provient des références Atlas fournies dans `design/atlas`.
