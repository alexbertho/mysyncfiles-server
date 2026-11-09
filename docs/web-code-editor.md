# Éditeur Python et C

L’explorateur ouvre les fichiers `.py` et `.c` dans une page dédiée, par double
clic ou avec **Modifier le code**. **Retour aux fichiers** retrouve le dossier
d’origine. Le code et la sortie défilent séparément ; leur séparateur se déplace
à la souris ou avec les flèches du clavier.

## Édition et raccourcis

L’éditeur reprend les couleurs, les contrôles et la taille de texte compacte de
l’explorateur : 13 px pour le code, la sortie et les commandes courantes, sans
agrandissement automatique sur les grands écrans. Les thèmes clair et sombre
partagent le réglage de l’explorateur. Sur mobile, la sortie passe sous le code.

La coloration distingue les mots-clés, fonctions, types, nombres, chaînes,
commentaires et directives. Les blocs Python/C peuvent être repliés dans la
marge ; la ligne courante, les parenthèses correspondantes et les occurrences
de la sélection sont mises en évidence. Des guides indiquent les niveaux
d’indentation ; le bouton **Afficher les espaces et tabulations** rend les
caractères d’espacement visibles sans les modifier.

- **Entrée** reprend l’indentation du bloc ; les parenthèses, crochets et
  guillemets sont fermés automatiquement.
- **Tab** indente, **Maj+Tab** désindente, y compris une sélection de plusieurs
  lignes. **Échap, puis Tab** permet de quitter le code au clavier.
- L’indentation est détectée à l’ouverture. La barre inférieure permet de
  choisir 2, 4 ou 8 espaces, ou des tabulations, pour les prochaines saisies.
- Les suggestions proposent des mots-clés, des symboles Python et des modèles
  de fonctions, boucles ou conditions. **Ctrl+Espace** les ouvre et **Entrée**
  valide ; **Tab** passe entre les champs d’un modèle.
- **Ctrl+F** ou **Ctrl+H** ouvre la recherche et le remplacement, avec options
  de casse, mot entier et expressions régulières ; **Ctrl+G** va à une ligne.
- **Ctrl+Z** annule et **Ctrl+Maj+Z** rétablit. **Ctrl+/** commente la sélection,
  **Ctrl+Maj+I** la réindente, **Alt+↑/↓** déplace une ligne et
  **Alt+Maj+↑/↓** la duplique.
- **Ctrl+D** ajoute l’occurrence suivante à la sélection ; **Ctrl+clic** ajoute
  un curseur et **Alt+glisser** crée une sélection rectangulaire.
- **Ctrl+S** demande la sauvegarde immédiate et **Ctrl+Entrée**
  exécute le fichier, après confirmation de sa sauvegarde.

Sur Mac, les commandes d’édition utilisent **⌘** à la place de **Ctrl**.
Le bouton d’aide récapitule les raccourcis. Les boutons au-dessus du code
donnent aussi accès à annuler/rétablir, rechercher, réindenter et activer le
retour à la ligne visuel, qui ne modifie pas le fichier. La barre inférieure
affiche la position du curseur, la sélection, l’indentation et les fins de ligne
LF/CRLF ; ces dernières sont conservées lors de la sauvegarde.

La complétion reste locale au navigateur ; elle ne consulte aucun service
externe et ne fournit pas d’analyse des dépendances d’un projet ou de serveur
de langage. L’éditeur s’appuie sur
[CodeMirror](https://codemirror.net/examples/basic/), livré avec l’interface.
Son historique d’annulation reste en mémoire dans l’onglet ; il ne constitue
pas un historique de versions du serveur.

## Autorisations

Le serveur et le client Linux doivent inclure l’éditeur, disponible à partir
de la version **0.3.13**. Sur un client déjà installé, lancer `mysync update`,
puis lancer `mysync restart` pour utiliser le nouveau binaire avec le service installé.

La lecture, l’édition et l’exécution sont des consentements distincts. Dans le
profil du client de ce PC, utiliser `mysync web-files enable`,
`mysync web-files enable-edit` et, pour exécuter, `mysync web-files enable-run`.
Les variantes `disable-edit` et `disable-run` retirent ces consentements.
Le [choix global de l’installation](install-client.md#installer-le-binaire-signe)
les accorde ensemble, avec oui proposé par défaut ; répondre non désactive tous
les droits web. Les profils existants conservent leurs choix.
Si le profil est occupé, lancer `systemctl --user stop mysync.service` avant de
le modifier, puis `mysync restart`. Pour un ancien client, utiliser
`systemctl --user daemon-reload && systemctl --user restart mysync.service`.
Pour un daemon lancé dans un terminal, Ctrl+C puis relancer sa commande.
Ces commandes ne démarrent aucun service et n’installent aucun outil.

Chaque autorisation web est liée au cookie de lecture, à l’appareil et à
l’enrôlement TPM approuvés. L’exécution est aussi liée à l’instance du pont
local qui a fourni la preuve. Elle exige un ticket à usage unique, valable
15 secondes, puis une vérification TPM auprès du serveur. Les tickets de
lecture, d’envoi et de gestion des dossiers ne donnent pas ces droits.
Le renouvellement de lecture conserve les autorisations supplémentaires sans
prolonger leur échéance. Atlas les renouvelle automatiquement par leurs propres
preuves locales avant expiration, sans interrompre l’édition ou une exécution
encore autorisée. Sans renouvellement, elles expirent au plus tard avec la
dernière session de lecture accordée. Un redémarrage du daemon change l’identité
de l’autorisation d’exécution et ne reprend pas un ancien lancement.

## Sauvegarde et conflits

Les fichiers doivent être du texte UTF-8, sans octet nul, et mesurer au maximum
256 Kio. La sauvegarde commence 100 ms après la dernière modification. Les
envois sont sérialisés et portent la révision de départ ; le serveur attribue
la nouvelle révision. Une réponse ancienne ne confirme jamais un nouveau texte.

Une modification concurrente bloque la sauvegarde et l’exécution. Le brouillon
reste dans l’éditeur et peut être téléchargé. Le serveur conserve également la
version refusée dans son dossier privé `.mysync-conflicts/`, avec un quota de
64 Mio et 4096 fichiers pour les conflits web. Si cette conservation échoue ou dépasse le quota,
le brouillon reste dans le navigateur et l’erreur est affichée. Les conflits du
client de synchronisation continuent d’utiliser son propre `.mysync-conflicts/`.
Il n’y a pas d’historique des écrasements ordinaires.

Le navigateur prévient avant de quitter un brouillon non confirmé. Le retour
aux fichiers attend la sauvegarde ; en cas d’erreur, télécharger ou résoudre le
brouillon avant de repartir. Les brouillons ne sont pas conservés dans le stockage
persistant du navigateur : ne pas forcer sa fermeture avant récupération.
L’indicateur **Enregistré** confirme la réponse du serveur ; **Modifié**,
**Enregistrement…** et **Sauvegarde interrompue** signalent les autres états.

## Exécution sur ce PC

**Exécuter** attend la confirmation du texte exact à lancer. Le client récupère
une copie de cette révision via une réponse signée par l’origine ; il ne lance
jamais du code fourni directement par une requête du navigateur. Le serveur
stocke et autorise les fichiers, sans les exécuter. La sortie indique quand le
code a changé depuis le lancement.

La première version utilise les outils système `python3`, ou `gcc` puis `clang`,
ainsi que `bubblewrap`, `prlimit` et un gestionnaire systemd utilisateur avec
les contrôleurs cgroup mémoire et processus. Si la détection ou une protection
échoue, le lancement est indisponible. Aucun outil n’est installé automatiquement.

Le programme travaille sur une copie isolée du seul fichier : pas d’accès au
miroir, au profil, au dossier personnel ou au réseau. Les outils et bibliothèques
système sont accessibles en lecture seule. Les fichiers temporaires sont
nettoyés. Il n’y a ni terminal interactif, ni projet multifichier, ni debugger.
Un seul lancement peut être actif à la fois sur ce client.

Les limites sont de 256 Mio de mémoire, 32 processus, un processeur, 16 Mio par
fichier temporaire, 64 Kio de sortie cumulée, 10 secondes de compilation et
5 secondes d’exécution. **Arrêter** interrompt aussi les processus enfants.
Sans renouvellement autorisé par le navigateur, le lancement s’arrête dans les
6 secondes ; l’expiration de session et la révocation empêchent ce renouvellement.
Les durées sont mesurées côté client, compilation et exécution séparément, et
incluent la mise en place de l’isolation.

L’isolation utilise les espaces de noms de
[Bubblewrap](https://github.com/containers/bubblewrap/blob/main/bwrap.xml)
et les limites de ressources de
[systemd](https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml).
Ces protections reposent sur le noyau Linux du PC.
