.PHONY: up exploit logs shell down
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
