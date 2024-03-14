#!/bin/bash

# This script installs all the dependencies to build this package

set -eu

# Install conda
curl https://repo.anaconda.com/pkgs/misc/gpgkeys/anaconda.asc | gpg --dearmor > /tmp/conda.gpg
sudo install -o root -g root -m 644 /tmp/conda.gpg /usr/share/keyrings/conda-archive-keyring.gpg
gpg --keyring /usr/share/keyrings/conda-archive-keyring.gpg --no-default-keyring --fingerprint 34161F5BF5EB1D4BFBBB8F0A8AEB4F8B29D82806
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/conda-archive-keyring.gpg] https://repo.anaconda.com/pkgs/misc/debrepo/conda stable main" | sudo tee /etc/apt/sources.list.d/conda.list > /dev/null
apt update
apt install -y conda
# shellcheck disable=SC2016
echo -e '\nexport PATH="/opt/conda/bin:$PATH' >> "$HOME/.bashrc"

# Install poetry
curl -sSL https://install.python-poetry.org | python3 -

# Install coookiecutter
sudo /opt/conda/bin/conda install --channel conda-forge --yes cookiecutter
