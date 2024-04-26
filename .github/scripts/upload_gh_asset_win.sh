IFS=',' read -ra ASSETS <<< "$4"
url="$3"
url=${url%%\{*}
for ASSET in "${ASSETS[@]}"; do
  ASSET_NAME=$(basename $ASSET)
  CONTENT_LENGTH=$(wc -c <"$ASSET")
  curl \
  -H "Authorization: Bearer $2" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  -H "Content-Length: $CONTENT_LENGTH" \
  -F "file=@$ASSET;type=$(file -b --mime-type $ASSET)" \
  "$url?name=$ASSET_NAME"
done