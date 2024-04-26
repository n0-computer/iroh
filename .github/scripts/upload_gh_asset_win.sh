IFS=',' read -ra ASSETS <<< "$4"
url="$3"
url=${url%%\{*}
for ASSET in "${ASSETS[@]}"; do
  ASSET_NAME=$(basename $ASSET)
  curl \
  -H "Authorization: Bearer $2" \
  -H "Content-Type: $(file -b --mime-type $ASSET)" \
  -H "X-GitHub-Api-Version: 2022-11-28" \
  --data-binary @"$ASSET" \
  "$url?name=$ASSET_NAME"
done