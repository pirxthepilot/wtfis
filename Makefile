PROJECT_NAME := wtfis
WTFIS_ENV_FILE := ${HOME}/.env.wtfis

# Build Docker image of the latest tagged commit
.PHONY: docker-image
docker-image:
	docker build -t $(PROJECT_NAME) --rm .

# Run and exec into the Docker image
.PHONY: docker-run
docker-run:
	docker run --env-file=$(WTFIS_ENV_FILE) -it wtfis
