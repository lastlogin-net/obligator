#!/bin/bash

version=$(git describe --tags)

./scripts/build_arch.sh linux x64
#./scripts/build_arch.sh linux 386
#./scripts/build_arch.sh linux arm
./scripts/build_arch.sh linux arm64
#./scripts/build_arch.sh freebsd 386
#./scripts/build_arch.sh freebsd arm
#./scripts/build_arch.sh freebsd arm64
#./scripts/build_arch.sh openbsd 386
#./scripts/build_arch.sh openbsd arm
#./scripts/build_arch.sh openbsd arm64
#./scripts/build_arch.sh windows 386 .exe
./scripts/build_arch.sh windows x64


tar -czf ./obligator_${version}.tar.gz build/
