#!/bin/bash

cd src/server

# Install the required packages
python -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# Start the server
python main.py $1 $2 $3 $4 $5 $6 $7 $8 $9