#!/bin/bash
#-------------------------------------------------------------------------------
# FILE: fix_format.bash
# USAGE: ./tools/fix_format.bash <directory>
# DESCRIPTION: Safely removes trailing whitespaces (W291, W293) and ensures a
#              single newline at the EOF (W292) for Python files. Outputs diffs.
# OPTIONS:
#    $1 : Target directory (default: src/)
# AUTHOR: Mario Luz
# VERSION: 1.0
#-------------------------------------------------------------------------------

set -e

TARGET="${1:-src/}"

#-------------------------------------------------------------------------------
# NAME: process_file
# DESCRIPTION: Strips trailing whitespace, fixes EOF newline, and shows diff.
# PARAMETER 1: File path
#-------------------------------------------------------------------------------
process_file() {
    local file="$1"
    local temp_file="${file}.tmp"
    
    cp "$file" "$temp_file"
    
    # Remove trailing whitespaces (spaces and tabs) at the end of lines
    sed -i 's/[[:blank:]]*$//' "$temp_file"
    
    # Ensure file ends with exactly one newline (awk 1 is POSIX compliant)
    awk 1 "$temp_file" > "${file}.awk" && mv "${file}.awk" "$temp_file"
    
    # Check if there are changes between original and temp file
    if ! cmp -s "$file" "$temp_file"; then
        echo "----------------------------------------------------------------"
        echo ">>> CHANGES FOUND IN: $file"
        echo "----------------------------------------------------------------"
        # Show unified diff (lines removed will have '-', added will have '+')
        diff -u "$file" "$temp_file" || true
        
        # Apply changes
        mv "$temp_file" "$file"
        echo "[APPLIED] $file"
        echo ""
    else
        # Discard temp file if no changes were needed
        rm "$temp_file"
    fi
}

# Find all Python files and process them
find "$TARGET" -type f -name "*.py" | while read -r py_file; do
    process_file "$py_file"
done

# Check main.py if it exists
if [[ -f "main.py" ]]; then
    process_file "main.py"
fi
