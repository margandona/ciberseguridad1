@echo off
echo =========================================
echo  SISTEMA DE AUTENTICACION SEGURO
echo =========================================
echo.

echo Verificando MongoDB...
tasklist /FI "IMAGENAME eq mongod.exe" 2>NUL | find /I /N "mongod.exe">NUL
if "%ERRORLEVEL%"=="0" (
    echo [OK] MongoDB esta ejecutandose
) else (
    echo [ADVERTENCIA] MongoDB no detectado
    echo Intentando iniciar MongoDB...
    net start MongoDB 2>NUL
    if errorlevel 1 (
        echo [ERROR] No se pudo iniciar MongoDB automaticamente
        echo Por favor, inicia MongoDB manualmente con: mongod
        pause
        exit /b 1
    )
)

echo.
echo Verificando dependencias...
if not exist "node_modules" (
    echo Instalando dependencias...
    npm install
    if errorlevel 1 (
        echo [ERROR] Fallo la instalacion de dependencias
        pause
        exit /b 1
    )
)

echo.
echo Verificando usuario administrador...
node setup-admin.js create-admin

echo.
echo =========================================
echo  INICIANDO SERVIDOR
echo =========================================
echo.
echo El servidor se iniciara en: http://localhost:3000
echo Para detener el servidor: Ctrl+C
echo.

npm start
