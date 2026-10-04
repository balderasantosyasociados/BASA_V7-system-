#!/bin/bash
# ==============================================================================
# SCRIPT DE AUTOMATIZACIÓN COMPLETA PARA CLOUDFLARE TUNNEL & DNS
# ==============================================================================
set -e

echo "=== 1. Instalando cloudflared si no existe ==="
if ! command -v cloudflared &> /dev/null
then
    echo "Descargando cloudflared..."
    wget -q https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64.deb
    sudo dpkg -i cloudflared-linux-amd64.deb
    rm -f cloudflared-linux-amd64.deb
    echo "cloudflared instalado con éxito."
else
    echo "cloudflared ya está instalado."
fi

echo "=== 2. Autenticación con Cloudflare ==="
echo "Por favor abre el enlace que aparecerá a continuación si aún no has iniciado sesión:"
cloudflared tunnel login

echo "=== 3. Creando túnel audit-trial ==="
cloudflared tunnel create audit-trial || true

echo "=== 4. Configurando DNS automático en Cloudflare ==="
cloudflared tunnel route dns audit-trial audit-intelligence-usa.com || true
cloudflared tunnel route dns audit-trial trial.audit-intelligence-usa.com || true

echo "=== 5. Copiando archivo de configuración config.yml ==="
mkdir -p ~/.cloudflared
cp config.yml ~/.cloudflared/config.yml || true

echo "=== 6. Iniciando túnel seguro ==="
echo "Tu aplicación ahora es accesible mundialmente en:"
echo "👉 https://audit-intelligence-usa.com/trial"
echo "👉 https://trial.audit-intelligence-usa.com"
cloudflared tunnel run audit-trial
