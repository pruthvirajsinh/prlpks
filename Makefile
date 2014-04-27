
#GODEPS=launchpad.net/godeps
GODEPS=github.com/cmars/godeps
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')

all: compile

compile:
	GOPATH=$(shell pwd)/build go install -ldflags "-X github.com/pruthvirajsinh/prlpks.Version ${VERSION}" github.com/pruthvirajsinh/prlpks/cmd/prlpks

build:
	GOPATH=$(shell pwd)/build make godeps compile

fmt:
	gofmt -w=true ./...

debs: debbin debsrc

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin: freeze-build
	debuild -us -uc -i -b

freeze-build:
	GOPATH=$(shell pwd)/build make 

freeze-godeps: require-godeps
	${GOPATH}/bin/godeps $(go list github.com/pruthvirajsinh/prlpks/...) > dependencies.tsv

require-godeps:	
	go install ${GODEPS}

clean:
	rm -rf build/bin build/pkg

copy-to-build:
	mv -f build ../
	rm -fr ../build/src/github.com/pruthvirajsinh/prlpks/*
	cp -fr * ../build/src/github.com/pruthvirajsinh/prlpks/
	mv -f ../build ./

copy-www:
	cp -fr $(shell pwd)/instroot/var/lib/prlpks/www $(shell pwd)/build/bin/ 


pkg-clean:
	rm -f ../prlpks_*.deb ../prlpks_*.dsc ../prlpks_*.changes ../prlpks_*.build ../prlpks_*.tar.gz 

.PHONY: copy-to-build all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps require-godeps clean pkg-clean build copy-www