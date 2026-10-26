@echo off
chcp 65001 > nul
title NetSpector - Generador de Informes

echo ========================================================
echo         NetSpector - Auditoría de Seguridad
echo ========================================================
echo.

where python >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Python detectado. Ejecutando NetSpector en modo interactivo...
    python "%~dp0generar_informe.py" %*
    if errorlevel 1 (
        echo.
        echo [!] Se ha producido un error durante la ejecucion de NetSpector (Codigo: %errorlevel%).
        echo [*] Revisa los mensajes anteriores para ver la causa del problema.
        echo.
        pause
    )
    goto end
)

where py >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Python Launcher detectado. Ejecutando NetSpector...
    py "%~dp0generar_informe.py" %*
    if errorlevel 1 (
        echo.
        echo [!] Se ha producido un error durante la ejecucion de NetSpector (Codigo: %errorlevel%).
        echo [*] Revisa los mensajes anteriores para ver la causa del problema.
        echo.
        pause
    )
    goto end
)

echo [!] Python no está instalado en este equipo o no se encuentra en el PATH.
echo [*] Abriendo la aplicación interactiva NetSpector en tu navegador...
echo.
if exist "%~dp0NetSpector.html" (
    start "" "%~dp0NetSpector.html"
) else (
    echo [!] Error: No se encuentra el archivo NetSpector.html en la carpeta del script.
    echo [*] Verifica que la instalacion del repositorio este completa.
    echo.
    pause
)

:end
