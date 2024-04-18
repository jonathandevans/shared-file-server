#!/bin/bash

cd src

if [ ! -f ca-key.pem ] || [ ! -f ca-cert.pem ]; then
    echo "Generating cert-auth.key and cert-auth.pem"
    openssl req -x509 -newkey rsa:2048 -keyout ca-key.pem -out ca-cert.pem -days 365 -nodes -subj "/CN=Certificate Authority"
fi

cd cert-auth

# Install the required packages
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Start the CA server
python main.py $1 $2 $3 $4 $5 $6 $7 $8 $9