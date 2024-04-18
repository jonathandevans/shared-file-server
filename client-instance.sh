#!/bin/bash

if [ -d "src/client-$1" ]; then
    cp -r src/client-$1/assets temp-assets
    rm -rf src/client-$1
    cp -r src/client src/client-$1
    cp -r temp-assets src/client-$1/assets
    rm -rf temp-assets
else
    cp -r src/client src/client-$1
fi

cd src/client-$1

# Install the required packages
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Start the client
python main.py $2 $3 $4 $5 $6 $7 $8 $9