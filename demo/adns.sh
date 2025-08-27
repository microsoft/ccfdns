set -ex

# Function to cleanup
cleanup() {
    echo "Cleaning up ADNS processes..."
    jobs -p | xargs -r kill 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM EXIT

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3 -m venv env
fi

source env/bin/activate
pip install -U -q pip
pip install -U -q ccf
pip install -q -U -r ../tests/requirements.txt
echo "Python environment successfully setup"

# Export where the VENV has been set, so tests running
# a sandbox.sh can inherit it rather create a new one
VENV_DIR=$(realpath env)
export VENV_DIR="$VENV_DIR"

# Enable https://github.com/Qix-/better-exceptions
export BETTER_EXCEPTIONS=1

export PYTHONPATH=$PYTHONPATH:/opt/ccf_virtual/bin

python3 ../tests/run_adns.py -b "/opt/ccf_virtual/bin" --library-dir ../build
