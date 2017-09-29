LDFLAGS="-w -s"
BUILD_DIR=`pwd`
GOPATH=`pwd`/vendor
OUTBIN="tk-ssh-authkeys"

PKG_NAME="tk-ssh-authkeys"
PKG_MAINTAINER="adam@trustedkey.com"
PKG_DESCRIPTION="Trusted Key SSH server authorized keys"
PKG_LICENSE="Unknown"
PKG_VERSION=`cat VERSION`

all: build

install:
	install -m 0755 $(OUTBIN) $(PREFIX)/bin/$(OUTBIN)

build:
	env CGO_ENABLED=0 GOPATH=$(GOPATH) go build -asmflags="-trimpath=$(BUILD_DIR)" -gcflags="-trimpath=$(BUILD_DIR)" -ldflags $(LDFLAGS) -o $(OUTBIN)

deb: build compress
	mkdir -p pkg/usr/bin/
	cp -a tk-ssh-authkeys pkg/usr/bin/
	fpm -f -s dir -t deb -v $(PKG_VERSION) -n $(PKG_NAME) --license=$(PKG_LICENSE) --maintainer=$(PKG_MAINTAINER) --description=$(PKG_DESCRIPTION) -a native -C pkg/
	./scripts/sign_deb.py --deb tk-ssh-authkeys_$(PKG_VERSION)_amd64.deb

rpm: build compress
	mkdir -p pkg/usr/bin/
	cp -a tk-ssh-authkeys pkg/usr/bin/
	fpm -f -s dir -t rpm -v $(PKG_VERSION) -n $(PKG_NAME) --license=$(PKG_LICENSE) --maintainer=$(PKG_MAINTAINER) --description=$(PKG_DESCRIPTION) -a native --rpm-sign -C pkg/

compress:
	upx $(OUTBIN)

clean:
	rm -rf pkg
	rm -f $(OUTBIN)
