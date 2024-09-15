#!/bin/bash

# ===============================================
# Script de Hardening para Servidor Web en Ubuntu 22.04 LTS
# ===============================================
# Este script implementa múltiples medidas de seguridad
# para fortalecer la configuración de un servidor Ubuntu
# que funciona como servidor web. Incluye:
#
# - Actualización del sistema y gestión de paquetes.
# - Configuración y endurecimiento del firewall UFW.
# - Desactivación de servicios innecesarios.
# - Instalación y configuración de ModSecurity como WAF.
# - Configuración y aplicación de perfiles de AppArmor.
# - Establecimiento de políticas de contraseñas más estrictas.
# - Endurecimiento de la configuración del kernel con sysctl.
# - Configuración segura del servicio SSH.
# - Generación de un inventario de seguridad.
# - Ejecución de Lynis para auditoría de seguridad.
#
# Además, se han añadido medidas adicionales para mejorar
# aún más la seguridad del servidor.
# ===============================================

# Verificar si el script se está ejecutando como root
if [ "$EUID" -ne 0 ]; then
  echo "Por favor, ejecuta este script como root."
  exit 1
fi

# Habilitar modo estricto: el script se detendrá ante cualquier error
set -e

# Directorio de instalación donde se guardarán los archivos generados
INSTALL_DIR="/root/instalacion"
mkdir -p "$INSTALL_DIR"

# Archivo de log donde se registrarán las acciones del script
LOGFILE="$INSTALL_DIR/hardening_log.txt"
exec > >(tee -i "$LOGFILE") 2>&1  # Redirigir salida estándar y errores al archivo de log

echo "Inicio del script de hardening para servidor web - $(date)"

# ===============================================
# Función para registrar errores en el log
# ===============================================
log_error() {
    echo "Error: $1 - $(date)" >> "$LOGFILE"
}

# ===============================================
# Función para verificar e instalar paquetes si no existen
# ===============================================
check_and_install() {
    local package=$1
    if dpkg -l | grep -qw "$package"; then
        echo "$package ya está instalado."
    else
        echo "Instalando $package..."
        if ! apt-get install -y "$package"; then
            log_error "Error al instalar $package."
            exit 1
        fi
    fi
}

# ===============================================
# Función para desactivar servicios innecesarios
# ===============================================
check_and_manage_service() {
    local service=$1
    if systemctl list-unit-files | grep -qw "$service.service"; then
        if systemctl is-active --quiet "$service"; then
            echo "Desactivando y deteniendo el servicio $service..."
            systemctl stop "$service"
            systemctl disable "$service"
            if [ $? -ne 0 ]; then
                log_error "Error al desactivar el servicio $service."
            fi
        else
            echo "El servicio $service no está activo."
        fi
    else
        echo "El servicio $service no está instalado."
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
# UFW (Uncomplicated Firewall) se utiliza para gestionar las reglas del firewall de forma sencilla.
echo "Instalando y configurando UFW..."
check_and_install "ufw"

# Configurar las políticas por defecto: denegar todas las conexiones entrantes y permitir las salientes
echo "Configurando UFW para denegar todas las conexiones entrantes y permitir las salientes..."
ufw default deny incoming
ufw default allow outgoing

# Permitir tráfico HTTP y HTTPS, esenciales para un servidor web
echo "Configurando UFW para permitir tráfico HTTP y HTTPS..."
ufw allow 80/tcp    # HTTP
ufw allow 443/tcp   # HTTPS

# Habilitar UFW para que las reglas entren en efecto
ufw enable
if [ $? -ne 0 ]; then
    log_error "Error al configurar UFW."
    exit 1
fi

# ===============================================
# Desactivación de servicios innecesarios
# ===============================================
# Desactivamos servicios que no son necesarios y pueden representar un riesgo de seguridad
echo "Desactivando servicios innecesarios..."
services_to_check=("rpcbind" "xinetd" "cups" "avahi-daemon")
for service in "${services_to_check[@]}"; do
    check_and_manage_service "$service"
done

# ===============================================
# Instalación y configuración de ModSecurity (WAF)
# ===============================================
# ModSecurity actúa como un Firewall de Aplicaciones Web, protegiendo contra ataques comunes
echo "Instalando y configurando ModSecurity..."
check_and_install "libapache2-mod-security2"

# Activar el módulo de seguridad en Apache
a2enmod security2

# Instalar el conjunto de reglas base de OWASP para ModSecurity
check_and_install "modsecurity-crs"
if [ ! -f /etc/modsecurity/crs/crs-setup.conf ]; then
    cp /usr/share/modsecurity-crs/crs-setup.conf.example /etc/modsecurity/crs/crs-setup.conf
fi

# Configurar ModSecurity para que esté en modo "On" en lugar de "DetectionOnly"
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/modsecurity/modsecurity.conf

# Reiniciar Apache para aplicar los cambios
systemctl restart apache2
if [ $? -ne 0 ]; then
    log_error "Error al reiniciar Apache después de configurar ModSecurity."
    exit 1
fi

# ===============================================
# Configuración de AppArmor para control de acceso
# ===============================================
# AppArmor ayuda a restringir las capacidades de las aplicaciones
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
# Configuramos políticas que requieren contraseñas más fuertes para todos los usuarios
echo "Configurando políticas de contraseñas..."
cat <<EOF > /etc/security/pwquality.conf
minlen = 12          # Longitud mínima de la contraseña
dcredit = -1         # Requiere al menos un dígito
ucredit = -1         # Requiere al menos una letra mayúscula
lcredit = -1         # Requiere al menos una letra minúscula
ocredit = -1         # Requiere al menos un carácter especial
retry = 3            # Número de intentos permitidos
EOF

# Asegurar que las políticas se apliquen también al usuario root
sed -i 's/# enforce_for_root/enforce_for_root/' /etc/pam.d/common-password

# ===============================================
# Endurecer la configuración del kernel con sysctl
# ===============================================
# Aplicamos configuraciones de seguridad al kernel para proteger contra ataques de red y mejorar la seguridad del sistema
echo "Endureciendo la configuración del kernel..."
cat <<EOF >> /etc/sysctl.conf
# Protecciones de red
net.ipv4.conf.all.rp_filter = 1                  # Habilita filtrado de direcciones IP spoofed
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_syncookies = 1                      # Protege contra ataques SYN flood
net.ipv4.conf.all.accept_source_route = 0        # Deshabilita rutas de origen
net.ipv4.conf.all.accept_redirects = 0           # Deshabilita redirecciones ICMP
net.ipv4.conf.all.secure_redirects = 1           # Acepta solo redirecciones ICMP seguras
net.ipv4.icmp_echo_ignore_broadcasts = 1         # Ignora peticiones ICMP broadcast
net.ipv4.icmp_ignore_bogus_error_responses = 1   # Ignora respuestas ICMP incorrectas
net.ipv4.conf.all.log_martians = 1               # Loguea paquetes con direcciones inválidas

# Protecciones de memoria
kernel.randomize_va_space = 2                    # Habilita aleatorización de direcciones de memoria (ASLR)
EOF

# Aplicar los cambios de sysctl
sysctl -p

# ===============================================
# Configuración de SSH (Secure Shell)
# ===============================================
# Configuramos SSH para mejorar su seguridad, deshabilitando el acceso root y estableciendo autenticación con claves
echo "Configurando SSH..."
echo "Introduce el nombre de usuario para el sistema SSH:"
read -r SSH_USER

# Verificar si el usuario existe; si no, crearlo
if id "$SSH_USER" &>/dev/null; then
    echo "El usuario $SSH_USER ya existe."
else
    echo "El usuario $SSH_USER no existe. Creándolo..."
    useradd -m -s /bin/bash "$SSH_USER"
    if [ $? -ne 0 ]; then
        log_error "Error al crear el usuario $SSH_USER."
        exit 1
    fi
    # Establecer una contraseña temporal (el administrador debe cambiarla después)
    echo "Establece una contraseña para el usuario $SSH_USER:"
    passwd "$SSH_USER"
fi

echo "Introduce el puerto para el servicio SSH (por defecto 22):"
read -r SSH_PORT
SSH_PORT=${SSH_PORT:-22}

SSH_HOME="/home/$SSH_USER"

# Crear el directorio .ssh si no existe y establecer los permisos correctos
mkdir -p "$SSH_HOME/.ssh"
chmod 700 "$SSH_HOME/.ssh"
chown "$SSH_USER:$SSH_USER" "$SSH_HOME/.ssh"

# Generar pares de claves SSH para el usuario especificado
echo "Generando pares de claves SSH para el usuario $SSH_USER..."
sudo -u "$SSH_USER" ssh-keygen -t rsa -b 4096 -f "$SSH_HOME/.ssh/id_rsa" -N "" -C "$SSH_USER@$(hostname)"
if [ $? -ne 0 ]; then
    log_error "Error al generar claves SSH."
    exit 1
fi

chmod 600 "$SSH_HOME/.ssh/id_rsa"
chmod 644 "$SSH_HOME/.ssh/id_rsa.pub"
chown "$SSH_USER:$SSH_USER" "$SSH_HOME/.ssh/id_rsa" "$SSH_HOME/.ssh/id_rsa.pub"

# Hacer copia de seguridad del archivo de configuración de SSH
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak

# Configurar SSH para deshabilitar el acceso root y la autenticación por contraseña
sed -i "s/^#*PermitRootLogin .*/PermitRootLogin no/" /etc/ssh/sshd_config
sed -i "s/^#*PasswordAuthentication .*/PasswordAuthentication no/" /etc/ssh/sshd_config
sed -i "s/^#*Port .*/Port $SSH_PORT/" /etc/ssh/sshd_config

# Verificar la configuración de SSH antes de reiniciar el servicio
if ! sshd -t; then
    log_error "Configuración de SSH inválida. Restaurando copia de seguridad."
    mv /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
    exit 1
fi

# Reiniciar el servicio SSH para aplicar los cambios
systemctl restart ssh
if [ $? -ne 0 ]; then
    log_error "Error al reiniciar el servicio SSH."
    exit 1
fi

# Actualizar las reglas del firewall para permitir conexiones SSH desde una IP específica
echo "Actualizando la configuración del firewall para permitir el puerto SSH $SSH_PORT desde la IP especificada."
echo "Por favor, introduce la IP que deseas usar para SSH y las reglas del firewall:"
read -r SERVER_IP

ufw allow from "$SERVER_IP" to any port "$SSH_PORT" proto tcp
if [ $? -ne 0 ]; then
    log_error "Error al actualizar la configuración del firewall para el puerto SSH."
    exit 1
fi

# Guardar información de la configuración SSH en un archivo
SSH_INFO="$INSTALL_DIR/ssh_info.txt"
{
    echo "Información de configuración de SSH:"
    echo "Nombre de usuario: $SSH_USER"
    echo "Ruta de claves SSH: $SSH_HOME/.ssh/id_rsa"
    echo "Clave pública SSH:"
    cat "$SSH_HOME/.ssh/id_rsa.pub"
    echo "Puerto SSH configurado: $SSH_PORT"
} > "$SSH_INFO"
if [ $? -ne 0 ]; then
    log_error "Error al crear archivo de información de SSH."
    exit 1
fi

# ===============================================
# Generación de inventario de seguridad
# ===============================================
# Crear un inventario detallado del sistema para fines de auditoría
echo "Generando inventario de seguridad..."
security_inventory="$INSTALL_DIR/security_inventory.txt"
{
    echo "Información del Sistema:"
    uname -a

    echo -e "\nPaquetes Instalados:"
    dpkg -l

    echo -e "\nServicios Activos:"
    systemctl list-units --type=service --state=running

    echo -e "\nServicios Habilitados:"
    systemctl list-unit-files --type=service --state=enabled

    echo -e "\nConfiguración de SSH:"
    grep -E '^PermitRootLogin|^PasswordAuthentication|^Port' /etc/ssh/sshd_config

    echo -e "\nEstado de AppArmor:"
    systemctl status apparmor

    echo -e "\nEstado de Firewall (UFW):"
    ufw status verbose

    echo -e "\nPermisos de Archivos Críticos:"
    ls -l /etc/shadow /etc/passwd /etc/gshadow /etc/group
} > "$security_inventory"
if [ $? -ne 0 ]; then
    log_error "Error al generar el inventario de seguridad."
    exit 1
fi

# ===============================================
# Ejecución de Lynis para auditoría de seguridad
# ===============================================
# Lynis es una herramienta que analiza el sistema y proporciona recomendaciones de seguridad
echo "Instalando y ejecutando Lynis..."
check_and_install "lynis"
lynis audit system > "$INSTALL_DIR/lynis_audit.txt"
if [ $? -ne 0 ]; then
    log_error "Error al ejecutar Lynis."
    exit 1
fi

# Guardar recomendaciones de endurecimiento de Lynis
echo "Aplicando configuraciones adicionales de seguridad recomendadas por Lynis..."
lynis hardening show > "$INSTALL_DIR/lynis_hardening_recommendations.txt"

# ===============================================
# Medidas adicionales de seguridad
# ===============================================
# Añadimos algunas configuraciones extra para mejorar la seguridad

# Configuración de actualizaciones automáticas de seguridad
echo "Configurando actualizaciones automáticas de seguridad..."
check_and_install "unattended-upgrades"
dpkg-reconfigure -plow unattended-upgrades

# Configuración de Fail2ban para proteger contra ataques de fuerza bruta
echo "Instalando y configurando Fail2ban..."
check_and_install "fail2ban"

# Crear una configuración básica para SSH
cat <<EOF > /etc/fail2ban/jail.local
[sshd]
enabled = true
port = $SSH_PORT
filter = sshd
logpath = /var/log/auth.log
maxretry = 5
EOF

# Reiniciar Fail2ban para aplicar la configuración
systemctl restart fail2ban
if [ $? -ne 0 ]; then
    log_error "Error al reiniciar Fail2ban."
    exit 1
fi

# Establecer permisos adecuados en archivos y directorios críticos
echo "Estableciendo permisos en archivos críticos..."
chmod 600 /etc/ssh/sshd_config
chmod 640 /etc/shadow
chmod 644 /etc/passwd
chmod 640 /etc/gshadow
chmod 644 /etc/group

# Deshabilitar el montaje de dispositivos USB (opcional, si no se necesitan)
echo "Deshabilitando montaje de dispositivos USB..."
echo "blacklist usb-storage" > /etc/modprobe.d/usb-storage.conf
update-initramfs -u

# ===============================================
# Finalización del script
# ===============================================
echo "Hardening completado - $(date)" >> "$LOGFILE"
echo "El script ha terminado. Todos los archivos de instalación se encuentran en el directorio $INSTALL_DIR."




