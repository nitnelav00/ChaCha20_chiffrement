#!/bin/bash

echo "Compilation de l'application..."
pyinstaller --onefile --name=chacha20_gui chacha20_gui.py
echo "Compilation terminée dans './dist'"
./dist/chacha20_gui