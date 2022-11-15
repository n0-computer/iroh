# install latest protocol buffer compiler. Yes, it's really this irritating.
# recent build URLs are missing "3" version prefix. version is actually "3.21.9"
PROTOC_VERSION=21.9
case ${TARGETPLATFORM} in
    "linux/amd64")  PROTOC_ZIP=protoc-21.9-linux-x86_64.zip  ;;
    "linux/arm64")  PROTOC_ZIP=protoc-21.9-linux-aarch_64.zip  ;;
  *) exit 1
esac

curl -OL https://github.com/protocolbuffers/protobuf/releases/download/v$PROTOC_VERSION/$PROTOC_ZIP
unzip -o $PROTOC_ZIP -d /usr/local bin/protoc
unzip -o $PROTOC_ZIP -d /usr/local 'include/*'
rm -f $PROTOC_ZIP
echo "installed $($PROTOC --version)"
