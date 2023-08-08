set -eu

# TODO: convert to rust

# Env
UDL_NAME="iroh"
FRAMEWORK_NAME="Iroh"
SWIFT_INTERFACE="IrohLib"

# Compile the rust
echo "Building aarch64-apple-ios"
cargo build -p iroh-ffi --manifest-path ../Cargo.toml --target aarch64-apple-ios
echo "Building aarch64-apple-ios-sim"
cargo build -p iroh-ffi --manifest-path ../Cargo.toml --target aarch64-apple-ios-sim
echo "Building x86_64-apple-ios"
cargo build -p iroh-ffi --manifest-path ../Cargo.toml --target x86_64-apple-ios

# Remove old files if they exist
IOS_ARM64_FRAMEWORK="$FRAMEWORK_NAME.xcframework/ios-arm64/$FRAMEWORK_NAME.framework"
IOS_SIM_FRAMEWORK="$FRAMEWORK_NAME.xcframework/ios-arm64_x86_64-simulator/$FRAMEWORK_NAME.framework"

rm -f "$IOS_ARM64_FRAMEWORK/$FRAMEWORK_NAME"
rm -f "$IOS_ARM64_FRAMEWORK/Headers/${UDL_NAME}FFI.h"
rm -f "$IOS_SIM_FRAMEWORK/$FRAMEWORK_NAME"
rm -f "$IOS_SIM_FRAMEWORK/Headers/${UDL_NAME}FFI.h"

rm -f ../target/universal.a
rm -f include/ios/*

# Make dirs if it doesn't exist
mkdir -p include/ios

# UniFfi bindgen
cargo run -p iroh-ffi --manifest-path ../Cargo.toml --bin uniffi-bindgen generate "src/$UDL_NAME.udl" --language swift --out-dir ./include/ios

# Make fat lib for sims
lipo -create \
    "../target/aarch64-apple-ios-sim/debug/lib${UDL_NAME}.a" \
    "../target/x86_64-apple-ios/debug/lib${UDL_NAME}.a" \
    -output ../target/universal.a

# Move binaries
cp "../target/aarch64-apple-ios/debug/lib${UDL_NAME}.a" \
    "$IOS_ARM64_FRAMEWORK/$FRAMEWORK_NAME"
cp ../target/universal.a \
    "$IOS_SIM_FRAMEWORK/$FRAMEWORK_NAME"

# Move headers
cp "include/ios/${UDL_NAME}FFI.h" \
    "$IOS_ARM64_FRAMEWORK/Headers/${UDL_NAME}FFI.h"
cp "include/ios/${UDL_NAME}FFI.h" \
    "$IOS_SIM_FRAMEWORK/Headers/${UDL_NAME}FFI.h"

# Move swift interface
sed "s/${UDL_NAME}FFI/$FRAMEWORK_NAME/g" "include/ios/$UDL_NAME.swift" > "include/ios/$SWIFT_INTERFACE.swift"

rm -f "$SWIFT_INTERFACE/Sources/$SWIFT_INTERFACE/$SWIFT_INTERFACE.swift"
cp "include/ios/$SWIFT_INTERFACE.swift" \
    "$SWIFT_INTERFACE/Sources/$SWIFT_INTERFACE/$SWIFT_INTERFACE.swift"

rm -rf "$SWIFT_INTERFACE/artifacts/*"
cp -R "$FRAMEWORK_NAME.xcframework" "$SWIFT_INTERFACE/artifacts/"
