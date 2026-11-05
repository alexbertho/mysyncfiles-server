.DEFAULT_GOAL := help

COMPOSE_SERVER = docker compose --env-file deploy/.env -f deploy/compose.yaml
COMPOSE_DOCS = docker compose --env-file deploy/.env.example -f deploy/compose.yaml --profile docs
MYSYNC_DOCS_DIR ?= /var/www/mysyncfiles/docs
MYSYNC_BUILD_MEMORY ?= 3g
MYSYNC_TEST_CPUS ?= 2
MYSYNC_CARGO_JOBS ?= 1
MYSYNC_BENCH_ARGS ?= --suite all --repetitions 3 --work-dir target

.PHONY: help check-config check-server-image install start stop logs get pair test test-unlocked benchmark test-integration deploy clean docs docs-stop docs-check docs-build editor-build editor-check

help:
	@printf '%s\n' \
		'make install     Vérifier deploy/.env et construire le serveur' \
		'make start       Démarrer le serveur' \
		'make stop        Arrêter le serveur sans supprimer les données' \
		'make logs        Suivre les journaux du serveur' \
		'make get         Afficher le Server ID, les appareils et le stockage' \
		'make pair        Appairer un client par son code temporaire' \
		'make test        Tests serveur et protocole, sans pilote ni simulateur TPM' \
		'make test-integration Échange client/serveur réel avec swtpm' \
		'make editor-build Reconstruire le moteur de l’éditeur web' \
		'make editor-check Vérifier le bundle de l’éditeur et ses licences' \
		'make benchmark   Mesurer le client et un serveur isolé avec un TPM simulé' \
		'make deploy      Tester, reconstruire et déployer le serveur et la documentation' \
		'make clean       Supprimer target/ et site/ (sans toucher aux données)' \
		'make docs        Voir la documentation sur http://127.0.0.1:8000' \
		'make docs-stop   Arrêter la prévisualisation' \
		'make docs-check  Construire et vérifier la documentation' \
		'make docs-build  Générer site/ avec l’origine HTTPS configurée'

editor-build:
	npm --prefix web ci --ignore-scripts --no-audit --no-fund
	npm --prefix web run build

editor-check:
	npm --prefix web ci --ignore-scripts --no-audit --no-fund
	npm --prefix web run check

check-config:
	@test -f deploy/.env || { printf '%s\n' "Copier deploy/.env.example vers deploy/.env et le configurer d'abord." >&2; exit 1; }
	$(COMPOSE_SERVER) config --quiet
	@for variable in MYSYNC_DATA_DIR; do \
		path=$$($(COMPOSE_SERVER) config --environment | sed -n "s/^$$variable=//p"); \
		case "$$path" in /*) ;; *) printf '%s doit être un chemin absolu.\n' "$$variable" >&2; exit 1;; esac; \
		test -d "$$path" || { printf '%s doit désigner un dossier existant.\n' "$$variable" >&2; exit 1; }; \
		done

check-server-image:
	@docker image inspect mysyncfiles-server:local >/dev/null 2>&1 || { printf '%s\n' 'Image serveur absente : lancer make install avant cette commande.' >&2; exit 1; }

install: check-config
	flock -n . docker buildx build --resource memory=$(MYSYNC_BUILD_MEMORY) \
		--resource memory-swap=$(MYSYNC_BUILD_MEMORY) --load \
		-t mysyncfiles-server:local -f deploy/Dockerfile .

start: check-config
	$(COMPOSE_SERVER) up -d --no-build server

stop:
	$(COMPOSE_SERVER) stop server

logs:
	$(COMPOSE_SERVER) logs -f server

get: check-config check-server-image
	$(COMPOSE_SERVER) run --rm --no-deps -T server info --data-dir /data

pair: check-config check-server-image
	$(COMPOSE_SERVER) run --rm server device pair --data-dir /data

test:
	@flock -n . $(MAKE) test-unlocked

test-unlocked:
	sh -n deploy/install-server.sh
	cargo fmt --all -- --check
	cargo test --locked --workspace --jobs $(MYSYNC_CARGO_JOBS)
	python3 -B -m unittest discover -s tests -p 'test_*.py'
	$(MAKE) docs-check

test-integration:
	./integration/test.sh


benchmark:
	./integration/test.sh --bench $(MYSYNC_BENCH_ARGS)


deploy:
	$(MAKE) test
	$(MAKE) check-config
	@command -v rsync >/dev/null && command -v sudo >/dev/null && test "$(MYSYNC_DOCS_DIR)" != / && sudo -v
	$(MAKE) install
	$(MAKE) docs-build
	$(COMPOSE_SERVER) up -d --no-build server
	sudo install -d -m 0755 "$(MYSYNC_DOCS_DIR)"
	sudo rsync -a --delete site/ "$(MYSYNC_DOCS_DIR)/"
	@printf '%s\n' 'Serveur et documentation déployés. Les releases clientes sont inchangées.' \
		'Les releases clientes se publient séparément depuis mysyncfiles-client.'

clean:
	cargo clean
	rm -rf site

docs:
	$(COMPOSE_DOCS) up -d --build docs

docs-stop:
	$(COMPOSE_DOCS) stop docs

docs-check:
	$(COMPOSE_DOCS) run --rm --build docs build --strict

docs-build: check-config check-server-image
	@public_url=$$($(COMPOSE_SERVER) run --rm --no-deps server device public-url --data-dir /data) || exit; \
	case "$$public_url" in https://*) ;; *) printf '%s\n' 'L’origine publique configurée doit utiliser HTTPS.' >&2; exit 1;; esac; \
	install -d -m 0755 site; \
	MYSYNC_PUBLIC_URL="$$public_url" MYSYNC_DOCS_SITE_URL="$$public_url/docs/" \
		$(COMPOSE_DOCS) run --rm --build --user "$$(id -u):$$(id -g)" \
		--volume "$$(pwd)/site:/workspace/site" \
		--env MYSYNC_PUBLIC_URL --env MYSYNC_DOCS_SITE_URL docs build --strict
