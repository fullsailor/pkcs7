PROJECT := go.mozilla.org/pkcs7

all: test vet lint

test:
	go test -covermode=count -coverprofile=coverage.out $(PROJECT)

showcoverage: test
	go tool cover -html=coverage.out

vet:
	go vet $(PROJECT)

lint:
	golint $(PROJECT)
