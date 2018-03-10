yq r $1  -j | jq -r  '.write_files[] | select(.path == "'"$2"'") | .content'  | base64 --decode
