#!/bin/bash

# Output file
output_file="generated_creds.txt"

# Characters to include (numbers and symbols)
chars="0123456789!@#$%^&*()_+-=<>?/|{}[]"

# Generate credentials with crunch and format them
crunch 7 7 "$chars" | awk '{print $0 ":" $0}' > "$output_file"

# Get file size
file_size=$(du -h "$output_file" | cut -f1)

echo "Credentials saved to $output_file (Size: $file_size)"
echo -n "Do you want to proceed? (y/n): "
read response

if [[ "$response" != "y" ]]; then
    echo "Operation aborted."
    rm "$output_file"
    exit 1
fi
