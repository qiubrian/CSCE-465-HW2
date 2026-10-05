# CSCE 465 Homework 2

## Setup

Create and activate Python virtual environment:

python3 -m venv .venv

source .venv/bin/activate

python -m pip install --upgrade pip

python -m pip install cryptography==49.0.0 pytest==9.1.1

cd into directory

python baseline_ctr.py

python handshake.py

python secure_record.py

python -m pytest -v
