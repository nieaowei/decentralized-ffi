#!/bin/bash
# This script builds local swift-bdk Swift language bindings and corresponding bdkFFI.xcframework.
# The results of this script can be used for locally testing your SPM package adding a local package
# to your application pointing at the bdk-swift directory.

HEADERPATH="Sources/DecentralizedFFI/DecentralizedFFIFFI.h"
MODMAPPATH="Sources/DecentralizedFFI/DecentralizedFFIFFI.modulemap"
TARGETDIR="../decentralized-ffi/target"
OUTDIR="."
RELDIR="release-smaller"
NAME="deffi"
STATIC_LIB_NAME="lib${NAME}.a"
NEW_HEADER_DIR="../decentralized-ffi/target/include"

# set required rust version and install component and targets
rustup default stable
rustup component add rust-src
rustup target add aarch64-apple-ios      # iOS arm64
rustup target add x86_64-apple-ios       # iOS x86_64
rustup target add aarch64-apple-ios-sim  # simulator mac M1
rustup target add aarch64-apple-darwin   # mac M1
rustup target add x86_64-apple-darwin    # mac x86_64

cd ../decentralized-ffi/ || exit

# build bdk-ffi rust lib for apple targets
cargo build --package decentralized-ffi --profile release-smaller --target x86_64-apple-darwin
cargo build --package decentralized-ffi --profile release-smaller --target aarch64-apple-darwin
cargo build --package decentralized-ffi --profile release-smaller --target x86_64-apple-ios
cargo build --package decentralized-ffi --profile release-smaller --target aarch64-apple-ios
cargo build --package decentralized-ffi --profile release-smaller --target aarch64-apple-ios-sim

# build bdk-ffi Swift bindings and put in bdk-swift Sources
cargo run --bin uniffi-bindgen generate --library ./target/aarch64-apple-ios/release-smaller/libdeffi.dylib --language swift --out-dir ../decentralized-swift/Sources/DecentralizedFFI --no-format

# combine bdk-ffi static libs for aarch64 and x86_64 targets via lipo tool
mkdir -p target/lipo-ios-sim/release-smaller
lipo target/aarch64-apple-ios-sim/release-smaller/libdeffi.a target/x86_64-apple-ios/release-smaller/libdeffi.a -create -output target/lipo-ios-sim/release-smaller/libdeffi.a
mkdir -p target/lipo-macos/release-smaller
lipo target/aarch64-apple-darwin/release-smaller/libdeffi.a target/x86_64-apple-darwin/release-smaller/libdeffi.a -create -output target/lipo-macos/release-smaller/libdeffi.a

cd ../decentralized-swift/ || exit

# move bdk-ffi static lib header files to temporary directory
mkdir -p "${NEW_HEADER_DIR}"
mv "${HEADERPATH}" "${NEW_HEADER_DIR}"
mv "${MODMAPPATH}" "${NEW_HEADER_DIR}/module.modulemap"
echo -e "\n" >> "${NEW_HEADER_DIR}/module.modulemap"

# remove old xcframework directory
rm -rf "${OUTDIR}/${NAME}.xcframework"

# create new xcframework directory from bdk-ffi static libs and headers
xcodebuild -create-xcframework \
    -library "${TARGETDIR}/lipo-macos/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/aarch64-apple-ios/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -library "${TARGETDIR}/lipo-ios-sim/${RELDIR}/${STATIC_LIB_NAME}" \
    -headers "${NEW_HEADER_DIR}" \
    -output "${OUTDIR}/${NAME}.xcframework"
