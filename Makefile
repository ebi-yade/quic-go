export GOOS:=linux
export GOARCH:=amd64

.PHONY: server client

server:
	cd example; \
	go build -o bin/server

client:
	cd example/client; \
	go build -o ../bin/client
