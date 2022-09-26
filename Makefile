debug:
	go build -o spnego-svc-debug main.go

release:
	go build -ldflags "-s -w" -o spnego-svc-release main.go
