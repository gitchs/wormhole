#!/bin/bash
export GOOS=${GOOS:="linux"}
export GOARCH=${GOARCH:="amd64"}


GIT_VERSION=`git log|head -n 1|awk '{print $2}'`

go build -v -ldflags "-X github.com/gitchs/wormhole/wormhole-server/initialization.VersionString=${GIT_VERSION}" ./

