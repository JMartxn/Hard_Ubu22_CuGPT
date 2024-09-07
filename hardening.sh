#!/bin/bash

# ===============================================
# Script de Hardening para Servidor Web en Ubuntu 22.04 LTS
# ===============================================
# Este script aplica varias medidas de seguridad
# para endurecer la configuración de Ubuntu y un servidor web.
# Incluye configuraciones específicas para servidores web,
# como la instalación de ModSecurity, firewall y protección
# de archivos y directorios.
# ===============================================

set -e  # Detener el script en caso de cualquier error

INSTALL_DIR="/root/instalacion"
mkdir -p $INSTALL_DIR

LOGFILE="$INSTALL_DIR/hardening_log.txt"
exec > >(tee -i $LOGFILE) 2>&1  # Redirigir salida estándar y errores al archivo de log

echo "Inicio del script de hardening para servidor web - $(date)"

# ===============================================
# Función para registrar errores en el log
# ===============================================
log_error() {
    echo "Error: $1 - $(date)" >> $LOGFILE
}

# ===============================================
# Solicitar IP del servidor
# ===============================================
# Para configurar adecuadamente las reglas del firewall,
# solicitamos al usuario la IP pública o privada del servidor.
# Esta IP se usará para limitar el acceso a servicios críticos
# como SSH, y para definir las reglas del firewall.
# ===============================================
echo "Por favor, introduce la IP que deseas usar para SSH y las reglas del firewall:"
read -r SERVER_IP

# ===============================================
# Función para verificar e instalar paquetes si no existen durante la instalación.
# ===============================================
# En esta sección, se instalan los siguientes paquetes si no están
# ya presentes en el sistema:
#
# 1. **`ufw`**: 
#    - UFW (Uncomplicated Firewall) es una herramienta sencilla
#      para gestionar las reglas del firewall. Nos permite
#      controlar el tráfico entrante y saliente de la red.
#
# 2. **`libapache2-mod-security2`**:
#    - ModSecurity es un firewall de aplicaciones web (WAF)
#      que protege el servidor web contra ataques comunes como
#      inyecciones SQL y XSS. Este módulo lo integra con Apache.
#
# 3. **`modsecurity-crs`**:
#    - Conjunto de reglas de OWASP (Core Rule Set) que se utiliza
#      junto con ModSecurity para detectar y prevenir amenazas
#      en aplicaciones web.
#
# 4. **`apparmor`**:
#    - AppArmor es un marco de seguridad que limita los permisos
#      de las aplicaciones a través de perfiles predefinidos, 
#      protegiendo el acceso a los recursos del sistema.
#
# 5. **`apparmor-profiles`**:
#    - Este paquete proporciona perfiles adicionales para AppArmor,
#      que aplican restricciones de acceso a aplicaciones comunes
#      como Apache o MySQL.
#
# 6. **`apparmor-utils`**:
#    - Herramientas adicionales para gestionar los perfiles de AppArmor,
#      como `aa-enforce`, que fuerza a las aplicaciones a usar estos perfiles.
#
# 7. **`lynis`**:
#    - Lynis es una herramienta de auditoría de seguridad que analiza
#      el sistema en busca de configuraciones inseguras y vulnerabilidades,
#      ofreciendo recomendaciones para mejorar la seguridad.
# ===============================================

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

# ===============================================
# Actualización del sistema
# ===============================================
echo "Actualizando el sistema..."
if ! apt-get update && apt-get upgrade -y; then
    log_error "Error al actualizar el sistema."
    exit 1
fi

# ===============================================
# Configuración del Firewall (UFW)
# ===============================================
# UFW (Uncomplicated Firewall) es una herramienta sencilla
# para la gestión de reglas de firewall en Ubuntu. En este
# servidor web, configuramos UFW para:
#
# 1. **Denegar todas las conexiones entrantes**:
#    Esto asegura que cualquier conexión no autorizada
#    que intente acceder al servidor será bloqueada, protegiendo
#    los servicios internos del servidor.
#    Comando: ufw default deny incoming
#
# 2. **Permitir todas las conexiones salientes**:
#    El servidor web puede iniciar conexiones hacia el exterior
#    (por ejemplo, para descargar actualizaciones), pero ningún
#    sistema externo puede iniciar conexiones al servidor excepto
#    en los puertos permitidos explícitamente.
#    Comando: ufw default allow outgoing
#
# 3. **Permitir conexiones SSH solo desde una IP específica**:
#    Se restringe el acceso al servicio SSH únicamente desde la IP
#    proporcionada por el administrador ($SERVER_IP), limitando
#    así el riesgo de ataques de fuerza bruta o acceso no autorizado.
#    Comando: ufw allow from $SERVER_IP to any port 22 proto tcp
#
# 4. **Permitir conexiones HTTP y HTTPS**:
#    Dado que este es un servidor web, se habilitan las conexiones
#    en los puertos 80 (HTTP) y 443 (HTTPS), permitiendo que los
#    clientes puedan acceder a las aplicaciones web del servidor.
#    Comandos: ufw allow 80/tcp (HTTP), ufw allow 443/tcp (HTTPS)
#
# Finalmente, se activa UFW y las reglas entran en funcionamiento.
# Esto asegura que solo el tráfico esencial y permitido pueda
# alcanzar el servidor web, mejorando considerablemente su seguridad.
# ===============================================

echo "Instalando y configurando UFW..."
check_and_install "ufw"

echo "Configurando UFW para denegar todas las conexiones entrantes y permitir las salientes..."
ufw default deny incoming
ufw default allow outgoing

echo "Permitiendo acceso SSH solo desde la IP especificada ($SERVER_IP)..."
ufw allow from $SERVER_IP to any port 22 proto tcp

echo "Configurando UFW para permitir tráfico HTTP y HTTPS..."
ufw allow 80/tcp  # HTTP
ufw allow 443/tcp  # HTTPS

ufw enable
if [ $? -ne 0 ]; then
    log_error "Error al configurar UFW."
    exit 1
fi

# ===============================================
# Desactivación de servicios innecesarios
# ===============================================
# rpcbind: Es un servicio utilizado para las comunicaciones RPC (Remote Procedure Call). 
# En un servidor web, generalmente no se necesita y puede ser una puerta de entrada para ataques.
# xinetd: Un superdemonio que gestiona otros servicios de red. En la mayoría de los servidores modernos, 
# es innecesario ya que los servicios como SSH y HTTP/HTTPS son gestionados por systemd o
# demonios dedicados como Apache/Nginx.
# cups: Es el servicio de impresión de Linux. En un servidor web, no hay necesidad de gestionar impresoras,
# por lo que es seguro desactivarlo.
# avahi-daemon: Es un servicio para el descubrimiento automático de dispositivos en redes locales (DNS Multicast). 
# Esto no es necesario en un servidor web, y podría ser un riesgo de seguridad si se deja habilitado.
# ===============================================
echo "Desactivando servicios innecesarios..."
services_to_check=("rpcbind" "xinetd" "cups" "avahi-daemon")
for service in "${services_to_check[@]}"; do
    check_and_manage_service $service
done

# ===============================================
# Instalación y configuración de ModSecurity (WAF)
# ===============================================
# ModSecurity es un WAF (Firewall de Aplicaciones Web)
# que protege el servidor web contra ataques como XSS,
# SQL Injection, y más. Se configura para funcionar con
# Apache, pero también está disponible para Nginx.
# ===============================================
echo "Instalando y configurando ModSecurity..."
check_and_install "libapache2-mod-security2"

# Activar el módulo de seguridad en Apache
a2enmod security2

# Descargar el conjunto de reglas base de OWASP para ModSecurity
check_and_install "modsecurity-crs"
cp /usr/share/modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf

# Activar las reglas básicas de seguridad de ModSecurity
cat <<EOF >> /etc/modsecurity/modsecurity.conf
SecRuleEngine On
EOF

# Reiniciar Apache para aplicar cambios
systemctl restart apache2
if [ $? -ne 0 ]; then
    log_error "Error al reiniciar Apache después de configurar ModSecurity."
    exit 1
fi

# ===============================================
# Configuración de AppArmor para control de acceso
# ===============================================
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
if [ $? -ne 0 ]; then
    log_error "Error al aplicar perfiles de AppArmor."
    exit 1
fi

# ===============================================
# Políticas de contraseñas más estrictas
# ===============================================
echo "Configurando políticas de contraseñas..."
cat <<EOF > /etc/security/pwquality.conf
minlen = 12
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
retry = 3
EOF

sed -i 's/# enforce_for_root/enforce_for_root/' /etc/pam.d/common-password

# ===============================================
# Endurecer la configuración del kernel con sysctl
# ===============================================
echo "Endureciendo la configuración del kernel..."
cat <<EOF >> /etc/sysctl.conf
# Protecciones de red
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.conf.all.log_martians = 1

# Protecciones de memoria
kernel.randomize_va_space = 2
EOF

sysctl -p

# ===============================================
# Configuración de SSH (Secure Shell)
# ===============================================
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

# ===============================================
# Generación de inventario de seguridad
# ===============================================
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

# ===============================================
# Ejecución de Lynis para auditoría de seguridad
# ===============================================
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




