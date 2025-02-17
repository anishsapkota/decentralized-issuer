#!/bin/bash

# Get the directory of the script
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
echo "Script is located in: $script_dir"

# Navigate to the 'keys' directory inside the script's location
cd "$script_dir/keys" || exit

# Remove .txt and .pem files
rm *.txt *.pem
