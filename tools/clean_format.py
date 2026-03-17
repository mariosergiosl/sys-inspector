#!/usr/bin/env python3
"""
FILE: clean_format.py
USAGE: python3 tools/clean_format.py
DESCRIPTION: Safely removes trailing whitespaces (W291, W293) and ensures a
             single newline at the EOF (W292) for Python files, handling CRLF.
OPTIONS: None
AUTHOR: Mario Luz
VERSION: 1.0
"""

import os


def clean_file(filepath):
    """
    NAME: clean_file
    DESCRIPTION: Reads a file, strips trailing whitespaces, enforces single EOF
                 newline, and rewrites the file using LF endings if changes exist.
    PARAMETER filepath: Absolute or relative path to the target file.
    """
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            lines = f.readlines()
    except UnicodeDecodeError:
        print(f"[SKIP] {filepath}: Not a valid UTF-8 file.")
        return

    if not lines:
        return

    cleaned_lines = []
    for line in lines:
        cleaned_line = line.rstrip(' \t\r\n')
        cleaned_lines.append(cleaned_line + '\n')

    while (
        len(cleaned_lines) > 1 and 
        cleaned_lines[-1] == '\n' and 
        cleaned_lines[-2] == '\n'
    ):
        cleaned_lines.pop()

    original_content = "".join(lines)
    new_content = "".join(cleaned_lines)

    if original_content != new_content:
        with open(filepath, 'w', encoding='utf-8', newline='\n') as f:
            f.write(new_content)
        print(f"[FIXED] {filepath}")


def main():
    """
    NAME: main
    DESCRIPTION: Entry point. Iterates over target directories and files.
    """
    targets = ['src', 'main.py']

    for target in targets:
        if os.path.isfile(target):
            if target.endswith('.py'):
                clean_file(target)
        elif os.path.isdir(target):
            for root, _, files in os.walk(target):
                for file in files:
                    if file.endswith('.py'):
                        filepath = os.path.join(root, file)
                        clean_file(filepath)
        else:
            print(f"[ERROR] Target not found: {target}")


if __name__ == '__main__':
    main()
