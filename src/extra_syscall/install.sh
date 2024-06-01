#!/bin/bash

# Source and destination directories
src_dir="$1"
dest_dir="$2"

# Check if source and destination directories are provided
if [ -z "$src_dir" ] || [ -z "$dest_dir" ]; then
  echo "Usage: $0 <source directory> <destination directory>"
  exit 1
fi

# Check if source directory exists
if [ ! -d "$src_dir" ]; then
  echo "Source directory does not exist: $src_dir"
  exit 1
fi

# Iterate over all files in the source directory, starting from the second level
find "$src_dir" -mindepth 2 -type f | while read -r file; do
  # Calculate relative path starting from the second level
  relative_path="${file#$src_dir/}"
  # Extract the second-level directory and below
  relative_path=$(echo "$relative_path" | cut -d'/' -f2-)
  # Construct target path
  target_path="$dest_dir/$relative_path"
  # Create target directory if it doesn't exist
  if [ ! -d "$(dirname "$target_path")" ]; then
    mkdir -p "$(dirname "$target_path")"
  fi
  # Copy file to target path
  cp "$file" "$target_path"
done

echo "Files have been successfully copied to: $dest_dir"
