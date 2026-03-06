#!/bin/bash

echo "Compilation de l'application..."
pyinstaller --onefile --name=chacha20_cli chacha20_cli.py
echo "Compilation terminée dans './dist'"
./dist/chacha20_cli