#/bin/bash

openssl ecparam -out data/ec_private_key.pem -name prime256v1 -genkey
openssl req -new -key data/ec_private_key.pem -x509 -nodes -days 365 -subj "/CN=83.212.99.99" -out data/mock_wallet_cert.pem