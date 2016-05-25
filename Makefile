PWD := $(shell dirname $(realpath $(lastword $(MAKEFILE_LIST))))

GOPKG = golang.struktur.de/spreedbox/spreedbox-auth
GOPATH = "$(CURDIR)/vendor:$(CURDIR)"
SYSTEM_GOPATH = /usr/share/gocode/src/

DIST := $(PWD)/dist
DIST_SRC := $(DIST)/src

FOLDERS = $(shell find -mindepth 1 -maxdepth 1 -type d -not -path "*.git" -not -path "*debian" -not -path "*vendor" -not -path "*doc" -not -path "*test" -not -path "*scripts" -not -path "*www")

VERSION := $(shell dpkg-parsechangelog | sed -n 's/^Version: //p')

NPM := $(shell which npm)
WWW_NPM_BIN := $(shell cd www && $(NPM) bin)
WWW_GULP = $(WWW_NPM_BIN)/gulp

all:

version:
	${ECHO} $(VERSION)

$(DIST_SRC):
	mkdir -p $@

dist_gopath: $(DIST_SRC)
	if [ -d "$(SYSTEM_GOPATH)" ]; then find $(SYSTEM_GOPATH) -mindepth 1 -maxdepth 1 -type d \
		-exec ln -sf {} $(DIST_SRC) \; ; fi
	if [ ! -d "$(SYSTEM_GOPATH)" ]; then find $(CURDIR)/vendor/src -mindepth 1 -maxdepth 1 -type d \
		-exec ln -sf {} $(DIST_SRC) \; ; fi

goget:
	if [ -z "$(DEB_BUILDING)" ]; then GOPATH=$(GOPATH) go get launchpad.net/godeps; fi
	if [ -z "$(DEB_BUILDING)" ]; then GOPATH=$(GOPATH) $(CURDIR)/vendor/bin/godeps -u dependencies.tsv; fi
	mkdir -p $(shell dirname "$(CURDIR)/vendor/src/$(GOPKG)")
	rm -f $(CURDIR)/vendor/src/$(GOPKG)
	ln -sf $(PWD) $(CURDIR)/vendor/src/$(GOPKG)

build: goget
	GOPATH=$(GOPATH) go build $(FOLDERS)

test: goget
	GOPATH=$(GOPATH) go test -v $(FOLDERS)

format:
	find $(FOLDERS) -name *.go -print0 | xargs -0 -n 1 go fmt

dependencies.tsv:
	set -e ;\
	TMP=$$(mktemp -d) ;\
	cp -r $(CURDIR)/vendor $$TMP ;\
	GOPATH=$$TMP/vendor:$(CURDIR) $(CURDIR)/vendor/bin/godeps $(GOPKG)/baddsch > $(CURDIR)/dependencies.tsv ;\
	rm -rf $$TMP ;\

clean: www-clean

www:
	cd $(CURDIR)/www && $(WWW_GULP) --release=$(VERSION)

www-clean:
	rm -rf $(CURDIR)/www/build || true

install-npm:
	cd $(CURDIR)/www && $(NPM) install

www-release: install-npm www

jscs:
	cd $(CURDIR)/www && $(WWW_GULP) jscs

.PHONY: all dist_gopath goget build dependencies.tsv www
