.PHONY: deploy
deploy:
	cd hstspreload.appspot.com && goapp deploy

.PHONY: serve
serve:
	cd hstspreload.appspot.com && goapp serve