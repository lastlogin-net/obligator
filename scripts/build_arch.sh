#!/bin/bash

os=$1
arch_name=$2

version=$(git describe --tags)
arch=$arch_name
file_extension=

if [[ "$os" == "windows" ]]
then
    export CC=x86_64-w64-mingw32-gcc
    file_extension=".exe"
fi

if [[ "$arch_name" == "arm64" ]]
then
    export CC=aarch64-linux-gnu-gcc
fi

if [[ "$arch_name" == "x64" ]]
then
    arch="amd64"
fi

filename=obligator-$os-${arch_name}-$version$file_extension

echo Building platform $os-$arch_name
CGO_ENABLED=1 GOOS=$os GOARCH=$arch go build \
    -C ./cmd/obligator \
    -ldflags "-extldflags=-static -X main.Version=$version" \
    -tags sqlite_omit_load_extension,netgo \
    -o ../../build/$filename

if [[ "$os" != "windows" ]]
then
    tar czf build/$filename.tar.gz -C build $filename
    rm build/$filename
fi
