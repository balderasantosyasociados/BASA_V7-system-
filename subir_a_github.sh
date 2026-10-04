#!/bin/bash
# ==============================================================================
# SCRIPT PARA SUBIR LOS ARCHIVOS DIRECTO A TU REPOSITORIO GITHUB:
# https://github.com/balderasantosyasociados/BASA_V7-system-
# ==============================================================================

echo "Subiendo actualización a GitHub BASA_V7-system-..."

git add app.py requirements.txt storage/clientes.json config.yml setup_tunnel.sh README.md
git commit -m "Integrar sistema de prueba de 3 dias para /trial con control matematico y Cloudflare Tunnel"
git push origin main

echo "¡Listo! Tu repositorio está 100% sincronizado y actualizado."
