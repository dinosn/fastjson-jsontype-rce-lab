.PHONY: up exploit logs shell down modern-safety modern-positive modern-controls
up:        ## build + start the lab
	docker compose up -d --build
exploit:   ## fire the one-payload RCE and show proof
	bash exploit/exploit.sh
logs:      ## tail both services
	docker compose logs -f
shell:     ## shell into the target container
	docker compose exec target sh
down:      ## stop + remove the lab
	docker compose down -v
modern-safety: ## verify the modern lab has no process-execution primitive
	cd modern-fd && ./scripts/static-safety-check.sh
modern-positive: ## run the marker-only Boot 3/JDK 17 fixed-DTO reproduction
	cd modern-fd && ./scripts/run-positive.sh
modern-controls: ## run ordinary/no-seed/wrong-FD/SafeMode controls
	cd modern-fd && ./scripts/run-controls.sh
