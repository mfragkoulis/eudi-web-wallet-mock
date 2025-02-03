#/usr/bin/env bash

curl -sSL https://install.python-poetry.org | python3 -
echo 'export PATH="/home/ubuntu/.local/bin:$PATH"' >> ~/.bash_profile
. ~/.bash_profile
poetry self add poetry-plugin-shell
poetry shell
poetry install

openssl ecparam -out data/ec_private_key.pem -name prime256v1 -genkey
openssl req -new -key data/ec_private_key.pem -x509 -nodes -days 365 -subj "/CN=83.212.72.114" -out data/mock_wallet_cert.pem
