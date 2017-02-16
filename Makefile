PROJECT := go.mozilla.org/pkcs7

all: test vet lint

test:
	go test $(PROJECT)

vet:
	go vet $(PROJECT)

lint:
	golint $(PROJECT)
