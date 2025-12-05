#!/bin/bash
#===============================================================================
#
# FILE: update_git.bash
#
# USAGE: update_git.bash [commit message]
#
# DESCRIPTION: This script updates a Git repository with the latest changes.
#              If a commit message is provided as an argument, it uses that.
#              Otherwise, it automatically uses a default message with the
#              list of changed files.
#              This script only runs if the 'run_python_test.bash' script
#              is successful.
#
# STEPS:       1. Runs automated tests (scripts/run_python_test.bash)
#              2. Updates Git (Add, Commit, Pull, Push, Tags)
#              3. Builds the Python package (Source + Wheel)
#              4. Publishes to official PyPI (Twine)
#
# OPTIONS:
#    -h, --help      Display this help message
#    -v, --version   Display script version
#
# REQUIREMENTS: git, python, run_python_test.bash
#
# BUGS:
#
# NOTES:
#
# AUTHOR:
#    Mario Luz (ml), mario.mssl[at]gmail.com
#
# COMPANY:
#
# VERSION: 2.4  # Updated version
# CREATED: 2024-11-18 17:00:00
# REVISION: 2025-06-27 11:22:00 # Updated revision date
# REVISION: 2025-12-05 14:48:00 # Updated for PyPI Automation
#===============================================================================

# Stop execution on any error
set -e

# Set script version
SCRIPT_VERSION="2.4"

# --- CONFIG ---
PROJECT_ROOT="/opt/host/Syncfolder/Trabalho/GitHub/mariosergiosl/sys-inspector"
BUILD_WORK_DIR="/opt/build_work"
# Define test script relative to current execution
SCRIPT_DIR=$(dirname "$(readlink -f "$0")")
TEST_SCRIPT="$SCRIPT_DIR/scripts/run_python_test.bash"
if [[ ! -f "$TEST_SCRIPT" ]]; then TEST_SCRIPT="scripts/run_python_test.bash"; fi


# Display help message
show_help() {
  cat << EOF
Usage: $0 [OPTIONS] [commit message]

This script updates a Git repository with the latest changes.
Full Release Pipeline: Test -> Git Push -> Build -> PyPI Upload

OPTIONS:
  -h, --help      Display this help message
  -v, --version   Display script version

Examples:
  $0 "My commit message"
  $0 -m "New feature: Network Scan"
  $0
EOF
}

# Display script version
show_version() {
  echo "$0 version $SCRIPT_VERSION"
}

# Get the commit message from the command line argument or prompt for one
# --- ARGUMENT PARSING ---
commit_message=""

while [[ $# -gt 0 ]]; do
  case $1 in
    -h|--help)
      show_help
      exit 0
      ;;
    -v|--version)
      echo show_version
      exit 0
      ;;
    -m)
      commit_message="$2"
      shift 2
      ;;
    *)
      if [[ -z "$commit_message" ]]; then
        commit_message="$1"
      fi
      shift
      ;;
  esac
done

# ==============================================================================
# STEP 1: TESTES (Safety First) - Run the Python tests
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">>> STEP 1: TESTES (Safety First) - Running Python tests..."
echo "----------------------------------------------------------------"

# Check if the python test script exists and run it
if [ -f "$TEST_SCRIPT" ]; then
    if /bin/bash $TEST_SCRIPT; then
        echo "Tests Passed. Proceeding..."
    else
        echo "!!! TESTS FAILED. Aborting Release !!!"
        exit 1
    fi
else
    echo "Warning: Test script '$TEST_SCRIPT' not found. Skipping tests."
fi

# ==============================================================================
# STEP 2: GIT AUTOMATION
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">>> STEP 2: GIT SYNC (Push & Tags)"
echo "----------------------------------------------------------------"

# heck if there are any staged changes to commit
if [[ -z $(git status --porcelain) ]]; then
    # Even if no changes to commit, still pull and push for tags in case
    # there are remote updates or only tags need pushing.
    echo "No local changes to add."
    echo "Pulling latest changes from remote repository..."
    git pull origin main
    git push origin main
    git push origin --tags
else
    # Auto-commit message if not exist
    if [[ -z "$commit_message" ]]; then
        # Get the list of updated files (now including newly added files)
        updated_files=$(git diff --cached --name-only)
        commit_message="Update: $updated_files"
        # Use the default commit message if none is provided via argument
        if [[ -z "$commit_message" ]]; then commit_message="Minor updates"; fi
    fi

    echo "Adding all changes (including new files) to staging area..."
    git add .

    echo "Committing with message: '$commit_message'"
    git commit -m "$commit_message"

    # Pull the latest changes from the remote repository BEFORE pushing local commits
    # This helps avoid conflicts if others have pushed
    echo "Pulling latest changes from remote repository..."
    # Commit the changes
    git pull origin main

    # Check for merge conflicts after pulling
    if [[ $(git status --porcelain | grep "^UU" | wc -l) -gt 0 ]]; then
        echo "!!! Merge conflicts detected after pulling. Please resolve them manually !!!"
        echo "Aborting push. Run 'git status' to see conflicted files."
        exit 1
    fi

    # Push the changes to the remote repository
    echo "Pushing changes to remote repository..."
    git push origin main

    # Push the tags to the remote repository
    echo "Pushing tags to remote repository..."    
    git push origin --tags
fi

# ==============================================================================
# STEP 3: BUILD & PUBLISH (PyPI)
# ==============================================================================
echo "----------------------------------------------------------------"
echo ">>> STEP 3: PYPI RELEASE"
echo "----------------------------------------------------------------"

# Check if tools are installed (using python module check for robustness)
if ! python3 -c "import twine" &> /dev/null || ! python3 -c "import build" &> /dev/null; then
    echo "Error: 'twine' or 'build' modules not found."
    echo "Try to install: pip install build twine"
    pip install build twine
    if [ $? -eq 1 ]; then
	echo "Error on try install: 'twine' or 'build' modules not found."
        exit 1
    fi
fi



# --- Check build folder /opt/build_work ---
echo "Preparing Clean Build Environment in $BUILD_WORK_DIR..."

# 1. Check if exist
if [ ! -d "$BUILD_WORK_DIR" ]; then
    echo "Directory $BUILD_WORK_DIR does not exist. Creating..."
    mkdir -p "$BUILD_WORK_DIR"
else
    # 3. Check is is empty
    if [ "$(ls -A $BUILD_WORK_DIR)" ]; then
         # 4. Not emppty, do backup
         TIMESTAMP=$(date +"%Y%m%d-%H%M%S")
         BACKUP_DIR="$BUILD_WORK_DIR/old_$TIMESTAMP"
         echo "Directory not empty. Moving content to $BACKUP_DIR..."
         mkdir -p "$BACKUP_DIR"
         
         # Move all (excpt the backup folder with has created now for do not make a loop)
         find "$BUILD_WORK_DIR" -maxdepth 1 -mindepth 1 -not -name "old_$TIMESTAMP" -exec mv {} "$BACKUP_DIR" \;
    fi
fi

echo "Copying project from $PROJECT_ROOT..."
cp -r "$PROJECT_ROOT" "$BUILD_WORK_DIR/sys-inspector"

cd "$BUILD_WORK_DIR/sys-inspector"


echo "1. Cleaning old build artifacts..."
rm -rf dist/ build/ src/*.egg-info

echo "2. Building package (Source + Wheel)..."
python3 -m build

if [ $? -eq 0 ]; then
    echo "Build Successful."

    # --- CORRECAO DE NOME PARA PYPI (Hifen -> Underscore) ---
    # O PyPI rejeita .tar.gz com hifen no nome do pacote.
    # Se encontrar arquivo com hifen, renomeia para underscore.
    for f in dist/*.tar.gz; do
        # if the file exist
        if [ -e "$f" ]; then
            # make the new name changing hifens for underscores on name of package
            # Ex: sys-inspector-0.30.9 -> sys_inspector-0.30.9
            base=$(basename "$f")
            new_name=$(echo "$base" | sed -E 's/^([a-zA-Z0-9]+)-([a-zA-Z0-9]+)/\1_\2/')
            
            if [ "$base" != "$new_name" ]; then
                echo "Renaming $base to $new_name for PyPI compliance..."
                mv "$f" "dist/$new_name"
            fi
        fi
    done
    # ---------------------------------------------------------

    echo "Files created in dist/:"
    ls -1 dist/
else
    echo "!!! BUILD FAILED. Aborting Upload !!!"
    exit 1
fi

echo "----------------------------------------------------------------"
echo "3. Uploading to PyPI..."
echo "Note: Using configuration from ~/.pypirc"
# The twine read your file ~/.pypirc automaticamente para autenticar
# twine upload dist/*
# Use python3 -m twine to bypass PATH issues
python3 -m twine upload dist/*


echo "----------------------------------------------------------------"
echo "Syncing artifacts back to source repo..."
if cp -r dist/* "$PROJECT_ROOT/dist/"; then
    echo "SUCCESS: Distribution files copied back to $PROJECT_ROOT/dist/"
else
    echo "WARNING: Could not copy files back to source directory."
    echo "The package was published successfully, but local artifacts are only in $BUILD_WORK_DIR/sys-inspector/dist/"
fi


echo "================================================================"
echo "   GRAND FINALE: SUCCESS! 🚀"
echo "   Code Pushed & Package Published to PyPI."
echo "================================================================"
