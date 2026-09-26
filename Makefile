.PHONY: help build up down test lint logs clean

help:
	@echo "PRISM Platform Commands:"
	@echo "  make up       - Start all containers via Docker Compose"
	@echo "  make down     - Stop all containers"
	@echo "  make build    - Rebuild Docker images"
	@echo "  make test     - Run Python unit test suite"
	@echo "  make dev      - Run local fullstack applet"
	@echo "  make logs     - Follow container logs"

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

test:
	python3 -m unittest backend/tests/test_all.py

dev:
	npm run dev

logs:
	docker compose logs -f

clean:
	docker compose down -v
	rm -rf dist node_modules
