#!/bin/bash
OSES=(linux darwin windows freebsd)
ARCHS=(amd64 386)
COMMIT=$(git log|head -n 1|awk '{print $2}')
for OS in ${OSES[@]};do
    for ARCH in ${ARCHS[@]};do
        filename="wormhole-client-${OS}-${ARCH}-${COMMIT}"
        GOOS="${OS}" GOARCH="${ARCH}" go build -o "$filename" ./
        xz "${filename}"
    done
done
