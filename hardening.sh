#!/bin/bash

# Script para aplicar medidas de hardening en Ubuntu 22.04 LTS

set -e  # Detener en caso de error

INSTALL_DIR="/root/instalacion"
mkdir -p $INSTALL_DIR

LOGFILE="$INSTALL_DIR/hardening_log.txt"
exec > >(tee -i $LOGFILE) 2>&1  # Redirigir salida y errores al log

echo "Inicio del script de hardening - $(date)"

log_error() {
    echo "Error: $1 - $(date)" >> $LOGFILE
}

check_and_install() {
    local package=$1
    if dpkg -l | grep -q "^ii  $package "; then
        echo "$package ya está instalado."
    else
        echo "Instalando $package..."
        if ! apt-get install -y $package; then
            log_error "Error al instalar $package."
            exit 1
        fi
    fi
}

check_and_manage_service() {
    local service=$1
    if systemctl is-active --quiet $service; then
        echo "El servicio $service está activo."
        echo "¿Deseas detener y desactivar el servicio $service? (y/n)"
        read -r response
        if [[ "$response" == "y" ]]; then
            if ! systemctl stop $service && systemctl disable $service; then
                log_error "Error al detener o desactivar el servicio $service."
                exit 1
            fi
        fi
    else
        echo "El servicio $service no está activo."
    fi
}

echo "Actualizando el sistema..."
if ! apt-get update && apt-get upgrade -y; then
    log_error "Error al actualizar el sistema."
    exit 1
fi

echo "Instalando y configurando UFW..."
check_and_install "ufw"

echo "Configurando UFW para denegar todas las conexiones entrantes y permitir las salientes..."
ufw default deny incoming
ufw default allow outgoing

echo "Permitiendo acceso SSH solo desde direcciones IP específicas (si es necesario)..."
# Sustituye 192.168.1.100 con la IP o rango que desees permitir
ufw allow from 192.168.1.100 to any port 22 proto tcp

ufw enable
if [ $? -ne 0 ]; then
    log_error "Error al configurar UFW."
    exit 1
fi

echo "Desactivando servicios innecesarios..."
services_to_check=("rpcbind" "xinetd" "cups" "avahi-daemon")
for service in "${services_to_check[@]}"; do
    check_and_manage_service $service
done

echo "Revisando y configurando AppArmor..."
check_and_install "apparmor"
systemctl enable apparmor
systemctl start apparmor
if [ $? -ne 0 ]; then
    log_error "Error al configurar AppArmor."
    exit 1
fi

echo "Aplicando reglas adicionales de seguridad de AppArmor..."
check_and_install "apparmor-profiles"
check_and_install "apparmor-utils"
aa-enforce /etc/apparmor.d/*

echo "Configurando SSH..."
echo "Introduce el nombre de usuario para el sistema SSH:"
read -r SSH_USER
echo "Introduce el puerto para el servicio SSH (por defecto 22):"
read -r SSH_PORT
SSH_PORT=${SSH_PORT:-22}

if [ ! -d "/home/$SSH_USER" ]; then
    log_error "El directorio del usuario $SSH_USER no existe."
    exit 1
fi

mkdir -p "/home/$SSH_USER/.ssh"
chmod 700 "/home/$SSH_USER/.ssh"

echo "Generando pares de claves SSH para el usuario $SSH_USER..."
ssh-keygen -t rsa -b 4096 -f "/home/$SSH_USER/.ssh/id_rsa" -N "" -C "$SSH_USER@$(hostname)"
if [ $? -ne 0 ]; then
    log_error "Error al generar claves SSH."
    exit 1
fi

chmod 600 "/home/$SSH_USER/.ssh/id_rsa"
chmod 644 "/home/$SSH_USER/.ssh/id_rsa.pub"

echo "Configurando SSH para deshabilitar el acceso root y la autenticación por contraseña..."
sed -i "s/#PermitRootLogin prohibit-password/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/#PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config

systemctl restart ssh
if [ $? -ne 0 ]; then
    log_error "Error al reiniciar el servicio SSH."
    exit 1
fi

echo "Actualizando la configuración del firewall para permitir el puerto SSH $SSH_PORT..."
ufw allow $SSH_PORT/tcp
if [ $? -ne 0 ]; then
    log_error "Error al actualizar la configuración del firewall para el puerto SSH."
    exit 1
fi

SSH_INFO="$INSTALL_DIR/ssh_info.txt"
{
    echo "Información de configuración de SSH:"
    echo "Nombre de usuario: $SSH_USER"
    echo "Ruta de claves SSH: /home/$SSH_USER/.ssh/id_rsa"
    echo "Clave pública SSH:"
    cat "/home/$SSH_USER/.ssh/id_rsa.pub"
    echo "Puerto SSH configurado: $SSH_PORT"
} > "$SSH_INFO"
if [ $? -ne 0 ]; then
    log_error "Error al crear archivo de información de SSH."
    exit 1
fi

echo "Generando inventario de seguridad..."
security_inventory="$INSTALL_DIR/security_inventory.txt"
{
    echo "Información del Sistema:"
    uname -a

    echo "Paquetes Instalados:"
    dpkg -l

    echo "Servicios Activos:"
    systemctl list-units --type=service --state=running

    echo "Servicios Habilitados:"
    systemctl list-unit-files --type=service --state=enabled

    echo "Configuración de SSH:"
    grep -E '^PermitRootLogin|^PasswordAuthentication|^Port' /etc/ssh/sshd_config

    echo "Estado de AppArmor:"
    systemctl status apparmor

    echo "Estado de Firewall (UFW):"
    ufw status verbose

    echo "Permisos de Archivos Críticos:"
    ls -l /etc/shadow /etc/passwd /etc/gshadow /etc/group
} > "$security_inventory"
if [ $? -ne 0 ]; then
    log_error "Error al generar el inventario de seguridad."
    exit 1
fi

echo "Instalando y ejecutando Lynis..."
check_and_install "lynis"
lynis audit system > "$INSTALL_DIR/lynis_audit.txt"
if [ $? -ne 0 ]; then
    log_error "Error al ejecutar Lynis."
    exit 1
fi

echo "Aplicando configuraciones adicionales de seguridad recomendadas por Lynis..."
lynis hardening show >> "$INSTALL_DIR/lynis_hardening_recommendations.txt"

echo "Hardening completado - $(date)" >> $LOGFILE
echo "El script ha terminado. Todos los archivos de instalación se encuentran en el directorio $INSTALL_DIR."
