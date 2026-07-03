.PHONY: build run ui docker clean

build:
	go build -o redlens.exe ./cmd/redlens

run: build
	./redlens.exe serve

ui:
	cd ui && npm run dev

docker:
	 docker-compose -f docker/docker-compose.yml up --build

clean:
	rm -f redlens.exe
	rm -rf reports/