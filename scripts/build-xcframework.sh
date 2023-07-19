# export RUSTFLAGS="-C embed-bitcode=yes"
# export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER="/usr/bin/clang"
# export LIBRARY_PATH="//usr/lib"
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="$HOME/.cargo/bin:$PATH"

REPO_ROOT=".."
RUST_FFI_DIR="../iroh-ffi"
OUT_DIR="../build"
BUILD_MACOS=false
# TODO(b5): explicitly enforce build toolchain for all cargo invocations
# RUST_TOOLCHAIN="1.71.0"

echo "1. Generate Iroh C header, copy Module map"
mkdir -p "${OUT_DIR}/include"
cargo test build_headers --features c-headers
mv ${RUST_FFI_DIR}/iroh.h ${OUT_DIR}/include/iroh.h
cp ${REPO_ROOT}/swift/include/module.modulemap ${OUT_DIR}/include/module.modulemap

echo "2. Build Iroh Libraries for Apple Platforms"

targets=(
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
  "aarch64-apple-ios"
  "x86_64-apple-ios"
  "aarch64-apple-ios-sim"
);

for target in "${targets[@]}"; do
  echo "compile for ${target}"
  cargo build --package iroh-ffi --release --target ${target}
  mkdir -p ${OUT_DIR}/${target}
  cp "${REPO_ROOT}/target/${target}/release/libiroh.a" "${OUT_DIR}/${target}/libiroh.a"
done

echo "3. Run Lipo"
if [ "$BUILD_MACOS" = true ]; then
  mkdir -p "${OUT_DIR}/apple-darwin-universal"
  lipo -create \
    "${OUT_DIR}/x86_64-apple-darwin/libiroh.a" \
    "${OUT_DIR}/aarch64-apple-darwin/libiroh.a" \
    -output "${OUT_DIR}/apple-darwin-universal/libiroh.a"
else 
  mkdir -p "${OUT_DIR}/ios-simulator-universal"
  lipo -create \
    "${OUT_DIR}/x86_64-apple-ios/libiroh.a" \
    "${OUT_DIR}/aarch64-apple-ios-sim/libiroh.a" \
    -output "${OUT_DIR}/ios-simulator-universal/libiroh.a"
fi

          

echo "4. Create XCFramework"

rm -rf ${REPO_ROOT}/target/LibIroh.xcframework

if [ "$BUILD_MACOS" = true ]; then
  xcodebuild -create-xcframework \
    -library ${OUT_DIR}/apple-darwin-universal/libiroh.a \
    -headers ${OUT_DIR}/include/ \
    -output ${REPO_ROOT}/target/LibIroh.xcframework
else
  xcodebuild -create-xcframework \
    -library ${OUT_DIR}/ios-simulator-universal/libiroh.a \
    -headers ${OUT_DIR}/include/ \
    -library ${OUT_DIR}/aarch64-apple-ios/libiroh.a \
    -headers ${OUT_DIR}/include/ \
    -output ${REPO_ROOT}/target/LibIroh.xcframework
fi


# echo "5. Zip XCFramework"
# zip -r ${REPO_ROOT}/target/libiroh-xcframework.zip ${REPO_ROOT}/target/LibIroh.xcframework

echo "Done"