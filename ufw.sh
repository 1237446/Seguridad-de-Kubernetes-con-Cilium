#!/bin/bash

# --- 1. VARIABLES ---
MASTERS="172.16.9.131 172.16.9.134"
WORKERS="172.16.9.132 172.16.9.133 172.16.9.135 172.16.9.136"
ALL_NODES="$MASTERS $WORKERS"
ADMIN_IP="172.16.8.208"

# --- 2. RESET Y CONFIGURACIÓN BASE (¡AQUÍ ESTABA EL PROBLEMA!) ---
echo "Limpiando reglas..."
ufw --force reset

# --- LA CORRECCIÓN CRÍTICA ---
# Forzar a UFW a permitir el reenvío de paquetes (Routing) para que los Pods hablen entre sí
sed -i 's/DEFAULT_FORWARD_POLICY="DROP"/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw
# -----------------------------

ufw default deny incoming
ufw default allow outgoing
sed -i 's/IPV6=yes/IPV6=no/g' /etc/default/ufw

# ====================================================
#   SECCIÓN A: INFRAESTRUCTURA (AGRUPADO POR PUERTO)
# ====================================================

echo ">>> Configurando K8s API (6443)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 6443 proto tcp comment "K8s API Internal"
done
ufw allow from $ADMIN_IP to any port 6443 proto tcp comment "K8s API Admin"

echo ">>> Configurando K8s Join (9345)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 9345 proto tcp comment "K8s Join"
done

echo ">>> Configurando Kubelet (10250)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 10250 proto tcp comment "Kubelet Metrics"
done

echo ">>> Configurando ETCD (2379-2380)..."
for ip in $MASTERS; do
    ufw allow from $ip to any port 2379 proto tcp comment "Etcd Client"
done
for ip in $MASTERS; do
    ufw allow from $ip to any port 2380 proto tcp comment "Etcd Peer"
done

# ====================================================
#   SECCIÓN B: RED CILIUM, HUBBLE y WIREGUARD
# ====================================================

echo ">>> Configurando Rutas de Pods (IMPORTANTE)..."
sudo ufw allow from 10.42.0.0/16 to any comment 'Cilium Pods CIDR'
sudo ufw allow from 10.43.0.0/16 to any comment 'K8s Services CIDR'


echo ">>> Configurando Cilium VXLAN (8472 UDP)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 8472 proto udp comment "Cilium VXLAN"
done
ufw allow in on cilium_vxlan comment "Cilium VXLAN Interface"
ufw allow out on cilium_vxlan comment "Cilium VXLAN Interface"

echo ">>> Configurando Cilium Health (4240)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 4240 proto tcp comment "Cilium Health"
done

ufw allow in on cilium_host comment "Cilium Host Interface"
ufw allow out on cilium_host comment "Cilium Host Interface"

echo ">>> Configurando WireGuard (51871 UDP)..."
for ip in $ALL_NODES; do
    ufw allow from $ip to any port 51871 proto udp comment "Cilium WireGuard"
done
ufw allow in on cilium_wg0 comment "Cilium WireGuard Interface"
ufw allow out on cilium_wg0 comment "Cilium WireGuard Interface"

echo ">>> Configurando Hubble Server/Peer (4244-4245)..."
sudo ufw allow 4244/tcp comment 'Hubble Server'
sudo ufw allow 4245/tcp comment 'Hubble Relay'
sudo ufw allow 4246/tcp comment 'Hubble UI'


# ====================================================
#   SECCIÓN C: ALMACENAMIENTO ROOK-CEPH
# ====================================================

# echo ">>> Configurando Ceph Monitors (6789, 3300)..."
# for ip in $ALL_NODES; do
#     ufw allow from $ip to any port 6789 proto tcp comment "Ceph Mon V1"
# done
# for ip in $ALL_NODES; do
#     ufw allow from $ip to any port 3300 proto tcp comment "Ceph Mon V2"
# done


# echo ">>> Configurando Ceph OSDs (6800:7300)..."
# for ip in $ALL_NODES; do
#     ufw allow from $ip to any port 6800:7300 proto tcp comment "Ceph OSD Range"
# done

# echo ">>> Configurando Ceph Metrics (9283)..."
# for ip in $ALL_NODES; do
#     ufw allow from $ip to any port 9283 proto tcp comment "Ceph Metrics"
# done

# ====================================================
#   SECCIÓN E: OTROS ACCESOS Y RUTAS
# ====================================================

echo ">>> Autorizando NodePorts..."
ufw allow from any to any port 30000:32767 proto tcp comment "K8s NodePorts"

echo ">>> Autorizando Bacula..."
sudo ufw allow 9101:9103/tcp comment 'Bacula Components'
sudo ufw allow 9097/tcp comment 'Bacularis Web'

# sudo ufw allow 9000/tcp comment 'MinIO API'
# sudo ufw allow 9001/tcp comment 'MinIO Console'

echo ">>> Configurando SSH Admin..."
sudo ufw allow ssh comment 'SSH Admin'
sudo ufw allow 6443/tcp comment 'API Admin'

# --- ACTIVAR ---
echo "Habilitando firewall..."
ufw enable
echo "Listo. Asegúrate de reiniciar los pods de Hubble."
