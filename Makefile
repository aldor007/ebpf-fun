all:
	go generate ./...
	rm bpf_bpfeb.go
	go build -o app *.go

fmt:
	go fmt *.go 
	go vet *.go

test:
	go test *.go -v 

docker-build:
	docker build  -t test-image  -f Dockerfile .

up:
	docker-compose build && docker-compose up