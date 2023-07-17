# export RUSTFLAGS="-C embed-bitcode=yes"
# export CARGO_TARGET_AARCH64_APPLE_IOS_SIM_LINKER="/usr/bin/clang"
# export LIBRARY_PATH="//usr/lib"
export PATH="/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin"
export PATH="$HOME/.cargo/bin:$PATH"

REPO_ROOT=".."
RUST_FFI_DIR="../iroh-ffi"
OUT_DIR="../build"
# TODO(b5): explicitly enforce build toolchain for all cargo invocations
# RUST_TOOLCHAIN="1.71.0"

echo "Generate Iroh C header, copy Module map"
mkdir -p "${OUT_DIR}/include"
cargo run --features c-headers --bin generate-headers
mv iroh.h ${OUT_DIR}/include/iroh.h
cp ${REPO_ROOT}/swift/include/module.modulemap ${OUT_DIR}/include/module.modulemap

echo "Build Iroh Libraries for Apple Platforms"

targets=(
  # "aarch64-apple-ios"
  # "x86_64-apple-ios"
  # "aarch64-apple-ios-sim"
  "x86_64-apple-darwin"
  "aarch64-apple-darwin"
)

for target in "${targets[@]}"; do
  cargo build --package iroh_ffi --release --target ${target}
  mkdir -p ${OUT_DIR}/lib_${target}
  cp "${REPO_ROOT}/target/${target}/release/libiroh_ffi.a" "${OUT_DIR}/lib_${target}/libiroh_ffi.a"
done

echo "Run Lipo"
mkdir -p "${OUT_DIR}/lib_ios-simulator-universal"
# cargo +`cat ${REPO_ROOT}/rust-toolchain` lipo \
#   --targets aarch64-apple-ios-sim,x86_64-apple-ios \
#   --manifest-path "${RUST_FFI_DIR}/Cargo.toml" 
# cp "${RUST_FFI_DIR}/target/universal/release/libiroh.a" "${OUT_DIR}/lib_ios-simulator-universal/libiroh.a"

lipo -create \
  "${OUT_DIR}/lib_x86_64-apple-ios/libiroh_ffi.a" \
  "${OUT_DIR}/lib_aarch64-apple-ios-sim/libiroh_ffi.a" \
  -output "${OUT_DIR}/lib_ios-simulator-universal/libiroh_ffi.a"
          

echo "Create XCFramework"

rm -rf ${REPO_ROOT}/target/LibIroh.xcframework

# xcodebuild -create-xcframework \
#   -library ${OUT_DIR}/lib_ios-simulator-universal/libiroh_ffi.a \
#   -headers ${OUT_DIR}/include/ \
#   -library ${OUT_DIR}/lib_aarch64-apple-ios/libiroh_ffi.a \
#   -headers ${OUT_DIR}/include/ \
#   -output ${REPO_ROOT}/target/LibIroh.xcframework

xcodebuild -create-xcframework \
  -library ${OUT_DIR}/lib_aarch64-apple-darwin/libiroh_ffi.a \
  -headers ${OUT_DIR}/include/ \
  -output ${REPO_ROOT}/target/LibIroh.xcframework

# echo "Zip XCFramework"
# zip -r ${REPO_ROOT}/target/libiroh-xcframework.zip ${REPO_ROOT}/target/LibIroh.xcframework

echo "Done"