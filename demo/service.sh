set -ex

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

python3 service.py --dns-name test.e2e.acidns10.attested.name --port 443 --adns 127.0.0.1:1443
