IFS=',' read -ra ASSETS <<< "$2"
for ASSET in "${ASSETS[@]}"; do
    ASSET_NAME=$(basename $ASSET)
    curl \
    -H "Authorization: Bearer $0" \
    -H "Content-Type: $(file -b --mime-type $ASSET)" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    --data-binary @"$ASSET" \
    "$1=$ASSET_NAME"
done