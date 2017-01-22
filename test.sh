#!/bin/bash
gometalinter --cyclo-over=20  --disable=gotype ./...  --json 
