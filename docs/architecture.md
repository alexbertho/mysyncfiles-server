# Architecture

MySyncFiles a deux composants : un serveur qui stocke les fichiers et tranche les révisions, et un client par appareil qui synchronise un dossier local. Le client peut effectuer un passage avec `mysync sync` ou surveiller le miroir en continu avec un service systemd utilisateur.

```text
Miroir local et TPM ── client mysync ── HTTPS ── proxy TLS ── serveur
                                                          │
                                            SQLite + fichiers + releases
```

Le serveur n'a pas de TPM. Le proxy transmet les requêtes mais ne décide ni de l'identité des appareils ni du contenu des fichiers. Les données traversant un proxy qui termine TLS y sont lisibles.

## Cycle d'un fichier

1. Le client lit le manifeste du serveur, puis compare ses révisions connues à l'état de son miroir.
2. Il envoie les modifications locales avec la révision de base observée. Les gros fichiers sont transférés par blocs d'au plus 8 Mio.
3. Le serveur accepte ou refuse l'opération selon sa révision courante et attribue la nouvelle révision.
4. Le client télécharge les changements distants. Si une version locale serait écartée, il la place dans `.mysync-conflicts/` avant de remplacer le fichier du miroir.

Une suppression apparaît comme une révision et peut être restaurée depuis la corbeille serveur pendant 30 jours. Un écrasement ordinaire n'a pas d'historique restaurable. Les dossiers vides et les liens symboliques ne sont pas synchronisés. Voir le [fonctionnement du client](client.md) et les [limites](security.md).

## Identité et mises à jour

Le daemon expose une [API de présence sur loopback](web-status.md), activée par défaut depuis la version 0.3.8 et désactivable à l’installation ou avec `mysync web-status disable`. Le navigateur transporte un challenge signé ; le daemon soumet sa preuve TPM directement au backend. La session de statut permet seulement de consulter le résultat temporaire. L’[explorateur Atlas](web-files.md) utilise un autre cookie et un challenge `files.read`, autorisé explicitement sur le client, pour un accès renouvelé automatiquement par des preuves locales. Chaque autorisation reste bornée à 30 minutes sans nouvelle preuve. Il n’existe toujours aucun modèle utilisateur ni espace de fichiers propre à une machine.

Chaque appareil crée une clé non exportable dans son TPM. Le client affiche un code que l'administrateur saisit localement sur le serveur ; le serveur vérifie ensuite la chaîne EK constructeur et l'appareil doit être approuvé après comparaison de l'empreinte. Le TPM signe l’ouverture et le renouvellement des sessions ; une clé Ed25519 temporaire en mémoire signe ensuite chaque requête de synchronisation. Les preuves web restent signées par le TPM. Le parcours manuel par invitation reste disponible. Voir le [guide d'identité](device-auth.md).

Le dépôt GitHub client distribue l’installateur et les releases, indépendamment des serveurs de synchronisation. Le manifeste de release est signé ; le client vérifie cette signature et le hash du binaire avant installation ou mise à jour. La clé privée de signature reste hors du serveur et des fichiers servis. Voir la [publication](operations.md#publier-un-client-signe).

Le dépôt serveur contient `crates/protocol` (messages, validation et signatures, sans pilote TPM). Le dépôt client utilise une révision Git précise de ce paquet et ne dépend pas du serveur ni de SQLite. Le serveur ne compile pas le client ni `tss-esapi`. La suite `integration/`, hors de la compilation courante, assemble les deux projets pour les tests réels.
