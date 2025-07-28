rm /usr/lib/libssl.so.3
rm /usr/lib/libcrypto.so.3
ln -s /opt/openssl/lib64/libssl.so.3 /usr/lib/libssl.so.3
ln -s /opt/openssl/lib64/libcrypto.so.3 /usr/lib/libcrypto.so.3