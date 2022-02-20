

SET GO111MODULE=on
SET GOPROXY=https://goproxy.cn,direct
SET CGO_ENABLED=0
SET GOOS=windows
SET GOARCH=amd64


go build -ldflags="-s -w" -o  tron-address-generate.exe main.go && E:\tools\upx-3.96-win64\upx -9 tron-address-generate.exe
