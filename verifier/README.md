# aDNS Verifier

Install Python dependencies:

```
pip install -r requirements.txt
```

Since ravl isn't necessarily installed system-wide, we need a few path settings.

Install local Python package:

```
CFLAGS="-I/path/to/ravl/include -L/path/to/ravl/build" python setup.py install
```

If it's not in the system paths, add ravl to `LD_LIBRARY_PATH` (we need `libravl.so`):

```
export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:/path/to/ravl/build
```

Run verifier:

```
python adns-verify.py service https://service43.test.attested.name:443/
python adns-verify.py delegation sub.test.attested.name
```

You may need a .pem file with CA certificates, e.g.

```
python adns-verify.py ... -c ./letsencrypt.pem
```
