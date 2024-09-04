#!/bin/bash
# /preseed/partitions.sh

LOGFILE="/preseed/partitions.log"
exec > >(tee -a $LOGFILE) 2>&1

log_message() {
    echo "$1 - $(date)"
}

log_error() {
    echo "Error: $1 - $(date)"
}

# Función para obtener el tamaño total del disco
get_disk_size() {
    local disk=$1
    fdisk -l $disk | grep 'Disk '$disk | awk '{print $5}'
}

# Función para mostrar el espacio total y recomendaciones
show_recommendations() {
    local total_size=$1
    local total_size_gb=$(echo "scale=2; $total_size/1024/1024/1024" | bc)
    echo "Tamaño total del disco: $total_size_gb GB"
    echo "Recomendaciones para el particionado:"
    echo "1. Partición EFI: 512 MB (suficiente para la mayoría de sistemas UEFI)"
    echo "2. Partición raíz (/): 20 GB - 50 GB dependiendo de tus necesidades"
    echo "3. Considera una partición de intercambio (swap) si tienes menos de 4 GB de RAM"
}

# Función para crear particiones
create_partitions() {
    local disk=$1
    local efi_size=$2
    local root_size=$3
    local swap_size=$4
    
    echo "Configurando particiones en $disk"
    (
        echo g   # Crear una nueva tabla de particiones GPT
        echo n   # Crear una nueva partición
        echo 1   # Número de partición
        echo     # Primer sector (default)
        echo +$efi_size  # Tamaño de la partición EFI
        echo t   # Cambiar tipo de partición
        echo 1   # Tipo de partición EFI
        echo n   # Crear una nueva partición
        echo 2   # Número de partición
        echo     # Primer sector (default)
        echo +$root_size  # Tamaño de la partición raíz
        echo n   # Crear una nueva partición (opcionalmente para swap)
        echo 3   # Número de partición
        echo     # Primer sector (default)
        echo +$swap_size   # Tamaño de la partición swap
        echo w   # Guardar cambios
    ) | fdisk $disk
    
    if [ $? -ne 0 ]; then
        log_error "Error al configurar las particiones con fdisk."
        exit 1
    fi
}

# Función para formatear particiones
format_partitions() {
    echo "Formateando particiones..."
    mkfs.vfat -F32 /dev/sda1
    mkfs.ext4 /dev/sda2
    if [ ! -z "$3" ]; then
        mkswap /dev/sda3
    fi

    if [ $? -ne 0 ]; then
        log_error "Error al formatear las particiones."
        exit 1
    fi
}

# Función para montar particiones
mount_partitions() {
    echo "Montando particiones..."
    mount /dev/sda2 /mnt
    mkdir -p /mnt/boot/efi
    mount /dev/sda1 /mnt/boot/efi
    if [ ! -z "$3" ]; then
        swapon /dev/sda3
    fi

    if [ $? -ne 0 ]; then
        log_error "Error al montar las particiones."
        exit 1
    fi
}

# Obtener el tamaño total del disco
DISK="/dev/sda"
TOTAL_SIZE=$(get_disk_size $DISK)
show_recommendations $TOTAL_SIZE

# Preguntar al usuario el tamaño para la partición EFI
echo "Introduce el tamaño para la partición EFI (por ejemplo, 512M o dejar en blanco para usar el valor por defecto de 512M):"
read EFI_SIZE
if [[ -z "$EFI_SIZE" ]]; then
    EFI_SIZE="512M"
fi

# Preguntar al usuario el tamaño para la partición raíz
echo "Introduce el tamaño para la partición raíz (por ejemplo, 20G para 20 gigabytes o dejar en blanco para usar el tamaño restante):"
read ROOT_SIZE
if [[ -z "$ROOT_SIZE" ]]; then
    ROOT_SIZE="20G"  # Valor por defecto para partición raíz
fi

# Preguntar al usuario el tamaño para la partición swap (opcional)
echo "Introduce el tamaño para la partición swap (por ejemplo, 2G para 2 gigabytes o dejar en blanco para no crear partición swap):"
read SWAP_SIZE

# Confirmar el tamaño de las particiones
echo "Resumen de particiones:"
echo "1. Partición EFI: $EFI_SIZE"
echo "2. Partición raíz (/): $ROOT_SIZE"
if [[ ! -z "$SWAP_SIZE" ]]; then
    echo "3. Partición swap: $SWAP_SIZE"
fi
echo "¿Deseas continuar con esta configuración? (y/n)"
read response
if [[ "$response" != "y" ]]; then
    echo "Configuración cancelada."
    exit 1
fi

# Crear particiones
create_partitions $DISK $EFI_SIZE $ROOT_SIZE $SWAP_SIZE

# Formatear particiones
format_partitions

# Montar particiones
mount_partitions

log_message "Particionado completado con éxito."
echo "Particionado completado. Revisa el archivo de log en $LOGFILE para más detalles."

