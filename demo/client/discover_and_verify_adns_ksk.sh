set -ex

ADNS_URL=$1

echo "Setting up Python environment..."
if [ ! -f "env/bin/activate" ]
    then
        python3 -m venv env
fi

source env/bin/activate
pip install -U -q pip
pip install -U -q ccf
pip install -q -U -r ../../tests/requirements.txt
echo "Python environment successfully setup"

# Export where the VENV has been set, so tests running
# a sandbox.sh can inherit it rather create a new one
VENV_DIR=$(realpath env)
export VENV_DIR="$VENV_DIR"

# Enable https://github.com/Qix-/better-exceptions
export BETTER_EXCEPTIONS=1

CCF_DIR="$(ls /opt | grep ccf_ | head -1)"
export PYTHONPATH=$PYTHONPATH:$CCF_DIR/bin:../../

python3 ksk.py --adns $ADNS_URL
