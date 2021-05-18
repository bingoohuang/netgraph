.PHONY: init install
all: init install

app=$(notdir $(shell pwd))

tool:
	go get github.com/securego/gosec/cmd/gosec

sec:
	@gosec ./...
	@echo "[OK] Go security check was completed!"

init:
	export GOPROXY=https://goproxy.cn

lint:
	#golangci-lint run --enable-all
	golangci-lint run ./...

fmt:
	gofumports -w .
	gofumpt -w .
	gofmt -s -w .
	go mod tidy
	go fmt ./...
	revive .
	goimports -w .

install: init
	go install -ldflags="-s -w" ./...
	ls -lh ~/go/bin/${app}

linux: init
	GOOS=linux GOARCH=amd64 go install -ldflags="-s -w" ./...

upx:
	ls -lh ~/go/bin/${app}
	upx ~/go/bin/${app}
	ls -lh ~/go/bin/${app}
	ls -lh ~/go/bin/linux_amd64/${app}
	upx ~/go/bin/linux_amd64/${app}
	ls -lh ~/go/bin/linux_amd64/${app}

test: init
	#go test -v ./...
	go test -v -race ./...

bench: init
	#go test -bench . ./...
	go test -tags bench -benchmem -bench . ./...

clean:
	rm coverage.out

cover:
	go test -v -race -coverpkg=./... -coverprofile=coverage.out ./...

coverview:
	go tool cover -html=coverage.out

# https://hub.docker.com/_/golang
# docker run --rm -v "$PWD":/usr/src/myapp -v "$HOME/dockergo":/go -w /usr/src/myapp golang make docker
# docker run --rm -it -v "$PWD":/usr/src/myapp -w /usr/src/myapp golang bash
# 静态连接 glibc
docker:
	mkdir -p ~/dockergo
	docker run --rm -v "$$PWD":/usr/src/myapp -v "$$HOME/dockergo":/go -w /usr/src/myapp mlallaouret/golang-libpcap:1.6 make dockerinstall
	upx ${app}

dockerinstall:
	go build -v -x -a -ldflags '-s -w -extldflags "-static"'

targz:
	cd .. && rm -f ${app}.tar.gz && tar czvf ${app}.tar.gz --exclude .git --exclude .idea ${app}

static:
	CGO_ENABLED=1 go build -a -tags netgo -ldflags '-w -s -extldflags "-static"' .

run:
	nohup ./netgraph -bpf "tcp and dst port 9090" -o stdout:replay -replay 192.166.223.29:9090 -replay.method=POST 2>&1 >> netgraph.log &

