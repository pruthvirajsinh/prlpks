
#GODEPS=launchpad.net/godeps
GODEPS=github.com/cmars/godeps
VERSION=$(shell head -1 debian/changelog | sed 's/.*(//;s/).*//;')

all: compile

compile:
	GOPATH=$(shell pwd)/build go install -ldflags "-X github.com/pruthvirajsinh/prlpks.Version ${VERSION}" github.com/pruthvirajsinh/prlpks/cmd/prlpks
	make -C doc

build:
	GOPATH=$(shell pwd)/build go get github.com/pruthvirajsinh/prlpks/...
	GOPATH=$(shell pwd)/build make godeps compile

godeps: require-godeps apply-godeps

fmt:
	gofmt -w=true ./...

debs: debbin debsrc

debsrc: debbin clean
	debuild -S -k0x879CF8AA8DDA301A

debbin: freeze-build
	debuild -us -uc -i -b

freeze-build:
	GOPATH=$(shell pwd)/build go get github.com/pruthvirajsinh/prlpks/...
	GOPATH=$(shell pwd)/build make apply-godeps

freeze-godeps: require-godeps
	${GOPATH}/bin/godeps $(go list github.com/pruthvirajsinh/prlpks/...) > dependencies.tsv

apply-godeps: require-godeps
	${GOPATH}/bin/godeps -u dependencies.tsv

require-godeps:
	go get -u ${GODEPS}
	go install ${GODEPS}

clean:
	rm -rf build/bin build/pkg

src-clean:
	rm -rf build

pkg-clean:
	rm -f ../prlpks_*.deb ../prlpks_*.dsc ../prlpks_*.changes ../prlpks_*.build ../prlpks_*.tar.gz 

.PHONY: all compile godeps fmt debs debsrc debbin freeze-build freeze-godeps apply-godeps require-godeps clean src-clean pkg-clean build
