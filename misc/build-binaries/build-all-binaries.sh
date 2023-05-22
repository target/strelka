#!/bin/bash

# This script is used to build Go binaries for multiple platforms.
# It should be run from the root of the Strelka directory. 
# The resulting executables will be output to the root of the Strelka directory.
#
# Each permutation of GOOS (operating system), GOARCH (architecture), and executable name
# is built using the Go build command.
#
# Before running this script, ensure that you have Go installed and that you are
# in the root of the Strelka directory. 
# You may have to run `chmod +x misc/build-binaries/build-all-binaries.sh` to make this script executable.

# Define arrays for goos, goarch, and executable
goos=("linux" "windows" "darwin" "darwin")
goarch=("amd64" "amd64" "amd64" "arm64")
executables=("strelka-fileshot" "strelka-filestream" "strelka-oneshot")
suffixes=("-linux" ".exe" "-mac64" "-macarm")

# Iterate over each permutation and build
for i in ${!goos[@]}; do
  for executable in ${executables[@]}; do
    GOOS=${goos[$i]} GOARCH=${goarch[$i]} go build -ldflags="-s -w" -o ${executable}${suffixes[$i]} src/go/cmd/${executable}/main.go
  done
done
