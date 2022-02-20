
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o tron-address-generate -v

upx -9 ./tron-address-generate