IFS=',' read -ra ASSETS <<< "$2"
url=$1
url=${url%%\{*}
for ASSET in "${ASSETS[@]}"; do
    ASSET_NAME=$(basename $ASSET)
    curl \
    -H "Authorization: Bearer $0" \
    -H "Content-Type: $(file -b --mime-type $ASSET)" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    --data-binary @"$ASSET" \
    "$url?name=$ASSET_NAME"
done