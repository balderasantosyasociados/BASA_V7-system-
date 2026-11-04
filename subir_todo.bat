@echo off
title SUBIENDO Y ACTIVANDO BASA V11 EN RENDER
echo ============================================================
echo   SUBIENDO AUTOMATICAMENTE A GITHUB Y RENDER (MODO FULL)
echo ============================================================

git status >nul 2>&1
if %errorlevel% neq 0 (
    echo Inicializando repositorio Git...
    git init
    git branch -M main
    git remote add origin https://github.com/balderasantosyasociados/BASA_V7-system-.git
)

git add app.py requirements.txt Procfile
git commit -m "feat: actualizacion full online Velrix Audit Intelligence V11 compatible movil y pc"
echo Subiendo cambios a GitHub...
git push -u origin main --force

echo.
echo ============================================================
echo   SUBIDA COMPLETADA CON EXITO
echo   Render detectara el cambio y desplegara en 1-2 minutos.
echo ============================================================
pause
