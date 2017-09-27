LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=`pwd`/vendor
OUTBIN="tk-ssh-authkeys"
PREFIX=/usr/local

all: build

install:
	install -m 0755 $(OUTBIN) $(PREFIX)/bin/$(OUTBIN)

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS) -o $(OUTBIN)

compress:
	upx --ultra-brute $(OUTBIN)

clean:
	rm -f $(OUTBIN)
