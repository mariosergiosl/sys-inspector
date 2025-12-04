#!/bin/bash
#===============================================================================
# FILE: scripts/run_python_test.bash
# DESCRIPTION: Runs linters on the src/ directory.
#===============================================================================

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

# Robust Path Detection:
# Gets the directory where THIS script is located (sys-inspector/scripts)
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
echo "SCRIPT_DIR: "$SCRIPT_DIR
# Points to the project root (sys-inspector/)
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
echo "PROJECT_ROOT: "$PROJECT_ROOT

echo "--- Setting up Environment ---"
echo "Project Root: $PROJECT_ROOT"

# Export PYTHONPATH relative to the project root
export PYTHONPATH="${PYTHONPATH}:${PROJECT_ROOT}/src"
echo "PYTHONPATH: "$PYTHONPATH

# Move to project root to run commands (so .pylintrc is found)
cd "$PROJECT_ROOT"

# 1. Flake8
echo -e "\n[1/2] Running Flake8..."
flake8 src/
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Flake8 Passed.${NC}"
else
    echo -e "${RED}Flake8 Failed.${NC}"
    exit 1
fi

# 2. Pylint
echo -e "\n[2/2] Running Pylint..."
pylint --rcfile=.pylintrc src/inspector.py src/sys_inspector/*.py
if [ $? -eq 0 ]; then
    echo -e "${GREEN}Pylint Passed.${NC}"
else
    echo -e "${RED}Pylint Failed.${NC}"
    exit 1
fi

echo -e "\n${GREEN}All tests passed successfully.${NC}"
