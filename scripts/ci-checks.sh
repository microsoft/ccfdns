#!/bin/bash
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the Apache 2.0 License.

set -e

if [ "$1" == "-f" ]; then
  FIX=1
else
  FIX=0
fi

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

ROOT_DIR=$( dirname "$SCRIPT_DIR" )
pushd "$ROOT_DIR" > /dev/null

# GitHub actions workflow commands: https://docs.github.com/en/actions/using-workflows/workflow-commands-for-github-actions
function group(){
    # Only do this in GitHub actions, where CI is defined according to
    # https://docs.github.com/en/actions/learn-github-actions/environment-variables#default-environment-variables
    if [[ ${CI} ]]; then
      echo "::group::$1"
    else
      echo "-=[ $1 ]=-"
    fi
}
function endgroup() {
    if [[ ${CI} ]]; then
      echo "::endgroup::"
    fi
}

# MASTER-TODO: enable this by removing the todos from the repo first.
# No inline TODOs in the codebase, use tickets, with a pointer to the code if necessary.
# group "TODOs"
# "$SCRIPT_DIR"/check-todo.sh .
# endgroup

group "C/C++/Proto format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-format.sh -f include src samples tests
else
  "$SCRIPT_DIR"/check-format.sh include src samples tests
fi
endgroup

group "TypeScript, JavaScript, Markdown, TypeSpec, YAML and JSON format"
npm install --loglevel=error --no-save prettier @typespec/prettier-plugin-typespec 1>/dev/null
if [ $FIX -ne 0 ]; then
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx prettier --write
else
  git ls-files | grep -e '\.ts$' -e '\.js$' -e '\.md$' -e '\.yaml$' -e '\.yml$' -e '\.json$' | grep -v -e 'tests/sandbox/' | xargs npx prettier --check
fi
endgroup

group "CMake format"
if [ $FIX -ne 0 ]; then
  "$SCRIPT_DIR"/check-cmake-format.sh -f cmake samples src tests CMakeLists.txt
else
  "$SCRIPT_DIR"/check-cmake-format.sh cmake samples src tests CMakeLists.txt
fi
endgroup

group "Python dependencies"
if [ ! -f "scripts/env/bin/activate" ]
    then
        python3 -m venv scripts/env
fi

source scripts/env/bin/activate
pip install -U wheel black mypy ruff 1>/dev/null
endgroup

group "Python format"
if [ $FIX -ne 0 ]; then
  git ls-files tests/ python/ scripts/ | grep -e '\.py$' | xargs black
else
  git ls-files tests/ python/ scripts/ | grep -e '\.py$' | xargs black --check
fi
endgroup

group "Python lint dependencies"
pip install -U -r tests/requirements.txt 1>/dev/null
endgroup

group "Python lint"
if [ $FIX -ne 0 ]; then
  ruff check --fix tests/
else
  ruff check tests/
fi
endgroup
