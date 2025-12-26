
#!/bin/sh
set -e

MODULE_NAME="kvx"

# Resolve repo root (script may be invoked from anywhere)
ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
KOBJ="${ROOT_DIR}/${MODULE_NAME}.ko"

cd "${ROOT_DIR}"

echo "[*] Cleaning previous build artifacts"
make clean

echo "[*] Building kernel module"
make

if [ ! -f "${KOBJ}" ]; then
    echo "[!] ERROR: ${MODULE_NAME}.ko was not produced"
    exit 1
fi

# Remove module if already loaded
if lsmod | grep -q "^${MODULE_NAME}\b"; then
    echo "[*] Removing existing module"
    sudo rmmod "${MODULE_NAME}"
fi

echo "[*] Inserting module"
sudo insmod "${KOBJ}"

echo "[*] Module inserted successfully"

echo "[*] Kernel log (recent, filtered)"
dmesg -T | tail -n 80 | sed -n "/${MODULE_NAME}/,\$p"
