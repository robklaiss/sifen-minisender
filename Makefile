COMPOSE ?= docker compose
CLI := $(COMPOSE) run --rm cli

XML ?= latest
PROTO ?=
RETRIES ?= 6
SLEEP ?= 10
ARTIFACTS_DIR ?= /data/artifacts

.PHONY: up down logs shell test check-env sample-xml send-test poll-test send-prod poll-prod smoke-local fix-perms

up:
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f web

shell:
	$(CLI) "bash"

test:
	$(CLI) "pytest -q"

check-env:
	./tools/check_env.sh .env

sample-xml:
	@mkdir -p data/artifacts
	@if [ -f templates/xml/rde_factura.xml ]; then \
		cp templates/xml/rde_factura.xml data/artifacts/sirecepde_sample.xml; \
		echo "XML de ejemplo: data/artifacts/sirecepde_sample.xml"; \
	else \
		echo "No se encontró templates/xml/rde_factura.xml"; \
		exit 1; \
	fi

send-test: check-env
	$(CLI) "xml_path=$$(python3 -m tools.prepare_xml_latest --xml '$(XML)' --artifacts-dir '$${SIFEN_ARTIFACTS_DIR:-$${ARTIFACTS_DIR:-/data/artifacts}}') && python3 -m tools.send_sirecepde --env test --xml \"$$xml_path\""

poll-test:
	@if [ -z "$(PROTO)" ]; then echo "Uso: make poll-test PROTO=<dProtConsLote> [RETRIES=6] [SLEEP=10]"; exit 1; fi
	$(CLI) "python3 -m tools.consulta_lote_poll --env test --prot '$(PROTO)' --retries $(RETRIES) --sleep $(SLEEP) --artifacts-dir '$${SIFEN_ARTIFACTS_DIR:-$${ARTIFACTS_DIR:-$(ARTIFACTS_DIR)}}'"

send-prod: check-env
	$(CLI) "xml_path=$$(python3 -m tools.prepare_xml_latest --xml '$(XML)' --artifacts-dir '$${SIFEN_ARTIFACTS_DIR:-$${ARTIFACTS_DIR:-/data/artifacts}}') && python3 -m tools.send_sirecepde --env prod --xml \"$$xml_path\""

poll-prod:
	@if [ -z "$(PROTO)" ]; then echo "Uso: make poll-prod PROTO=<dProtConsLote> [RETRIES=6] [SLEEP=10]"; exit 1; fi
	$(CLI) "python3 -m tools.consulta_lote_poll --env prod --prot '$(PROTO)' --retries $(RETRIES) --sleep $(SLEEP) --artifacts-dir '$${SIFEN_ARTIFACTS_DIR:-$${ARTIFACTS_DIR:-$(ARTIFACTS_DIR)}}'"

smoke-local:
	./.venv/bin/python tools/smoke.py --env test

fix-perms:
	./scripts/fix_data_perms.sh
