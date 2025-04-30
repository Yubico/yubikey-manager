#!/bin/sh

# Runs pyright from poetry
set -e

if [ "$(poetry env list)" = "" ]; then
	echo "Initializing poetry env..."
	poetry install
fi

poetry run pyright yubikit
