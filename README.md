# Seguridad-de-Kubernetes-con-Cilium
Esta guía detalla cómo asegurar los nodos de un clúster Kubernetes utilizando **UFW** (seguridad a nivel de host) en conjunto con **Cilium** (seguridad y red a nivel de Pod, con encriptación WireGuard).

Es vital distinguir las capas de seguridad para evitar cortes de servicio:

* **UFW (Host Firewall):** Protege el Sistema Operativo (Ubuntu/Debian). Su función es bloquear acceso SSH no autorizado y limitar qué puertos del nodo son visibles hacia internet o la red corporativa.
* **Cilium (CNI):** Gestiona la red interna de los contenedores. UFW **no** debe interferir con la comunicación interna de los Pods ni con las interfaces virtuales que Cilium crea (`cilium_host`, `cilium_vxlan`, `cilium_wg0`).

---
## UFW (Uncomplicated Firewall o Cortafuegos No Complicado)
UFW es una interfaz de gestión simplificada para el sistema de filtrado de paquetes de Linux (netfilter/iptables).

En Kubernetes, la gestión de redes es compleja porque K8s manipula dinámicamente las reglas de iptables para que los servicios y pods se comuniquen. Pero La utilidad principal de UFW en K8s no es gestionar la red de los contenedores, sino proteger al Nodo (el servidor host).

  * Seguridad del Host: Protege el sistema operativo base de accesos SSH no autorizados o escaneos de puertos externos.
  
  * Segmentación: Asegura que solo los puertos necesarios para el funcionamiento del clúster (API Server, Kubelet, Etcd) estén expuestos a las redes correctas.

### Pre-requisitos Críticos (Configuración del Sistema)

> [\!WARNING]
>  No saltes este paso. Si activas UFW sin habilitar el reenvío de paquetes, los Pods no podrán resolver DNS ni comunicarse entre sí.

#### A. Habilitar IP Forwarding

Kubernetes requiere que el tráfico pueda pasar a través del nodo hacia los contenedores.

1. Edita la configuración predeterminada de UFW:
```bash
sudo nano /etc/default/ufw

```

2. Busca y modifica la política de reenvío:
```bash
# Cambiar DROP por ACCEPT
DEFAULT_FORWARD_POLICY="ACCEPT"

```

3. Aplica los cambios (sin activar el firewall todavía):
```bash
sudo ufw reload

```

#### B. Definir Variables (Para facilitar el copiado)

Antes de ejecutar las reglas, define estas variables en tu terminal según tu entorno:

```bash
# Rango de IPs de tus Nodos (Ej. 192.168.1.0/24)
export K8S_NODES_CIDR="192.168.1.0/24"
# Tu IP de administración (para SSH y API seguro)
export ADMIN_IP="203.0.113.5"
# CIDR de los Pods (Por defecto en Cilium suele ser 10.0.0.0/8 o similar)
export POD_CIDR="10.42.0.0/16"
# CIDR de los Servicios
export SVC_CIDR="10.43.0.0/16"

```

---

### Implementación de Reglas

#### Fase 1: Acceso Administrativo y Base

Primero, asegúrate de no quedarte fuera del servidor.

```bash
# 1. Resetear reglas previas para empezar limpio
sudo ufw reset

# 2. Denegar todo el tráfico entrante por defecto
sudo ufw default deny incoming

# 3. Permitir todo el tráfico saliente
sudo ufw default allow outgoing

# 4. Permitir SSH (Idealmente solo desde tu IP, o 'limit' para evitar fuerza bruta)
sudo ufw allow from $ADMIN_IP to any port 22 proto tcp
# O si necesitas acceso general: sudo ufw limit 22/tcp

# 5. Permitir acceso a la API de Kubernetes (Solo Admin y Nodos)
sudo ufw allow from $ADMIN_IP to any port 6443 proto tcp
sudo ufw allow from $K8S_NODES_CIDR to any port 6443 proto tcp

```

#### Fase 2: Comunicación entre Nodos (Kubernetes Core)

Los nodos deben hablar entre sí sin restricciones para Etcd, Kubelet y métricas.

```bash
# 6. Kubelet API (Salud de nodos y métricas)
sudo ufw allow from $K8S_NODES_CIDR to any port 10250 proto tcp

# 7. Etcd (Solo si es un nodo Control Plane/Master)
sudo ufw allow from $K8S_NODES_CIDR to any port 2379:2380 proto tcp

# 8. RKE2/K3s Server (Si usas RKE2 en lugar de K8s vainilla, puerto 9345)
sudo ufw allow from $K8S_NODES_CIDR to any port 9345 proto tcp

# 9. NodePorts (Rango por defecto para servicios tipo NodePort)
# Nota: Esto abre el rango a CUALQUIER IP. Si usas MetalLB, esto es menos crítico.
sudo ufw allow 30000:32767/tcp

```

#### Fase 3: Reglas Específicas para Cilium + WireGuard

Cilium necesita puertos específicos para la encapsulación (VXLAN/Geneve) y la encriptación (WireGuard), además de sus interfaces virtuales.

```bash
# 10. Cilium VXLAN (Tráfico de red superpuesta)
sudo ufw allow from $K8S_NODES_CIDR to any port 8472 proto udp

# 11. Cilium Health Checks
sudo ufw allow from $K8S_NODES_CIDR to any port 4240 proto tcp

# 12. Cilium WireGuard (Encriptación)
# El puerto por defecto es 51871 UDP
sudo ufw allow from $K8S_NODES_CIDR to any port 51871 proto udp

# 13. Confianza en Interfaces Virtuales de Cilium
# Es CRÍTICO permitir tráfico en las interfaces que crea Cilium
sudo ufw allow in on cilium_vxlan to any
sudo ufw allow in on cilium_host to any
sudo ufw allow in on cilium_wg0 to any

# 14. Permitir tráfico desde los rangos de Pods y Servicios
sudo ufw allow from $POD_CIDR
sudo ufw allow from $SVC_CIDR

```

#### Fase 4: Observabilidad (Hubble) - Opcional

Si usas Hubble para ver el mapa de red, asegura estos puertos (idealmente no exponerlos a internet abierta).

```bash
# Hubble Relay y Server (Solo desde red interna o Admin)
sudo ufw allow from $K8S_NODES_CIDR to any port 4244:4245 proto tcp
# Hubble UI (Si accedes vía port-forward no es necesario abrirlo, si usas NodePort sí)
# sudo ufw allow from $ADMIN_IP to any port 4246 proto tcp

```

> [\!TIP]
> Si desea automatizar la aplicacion de reglas puede usar el script UFW.sh para una aplicacion rapida, sin olvidar editar las variables 

---

#### Consideración Especial: MetalLB

UFW puede interferir con MetalLB dependiendo del modo:

* **Modo Layer 2 (ARP):** Generalmente funciona bien con las reglas anteriores. El tráfico llega al puerto del servicio y kube-proxy/cilium lo maneja.
* **Modo BGP:** Si configuras MetalLB con BGP, necesitas permitir el puerto **179 TCP** entre los nodos y tu router.
```bash
sudo ufw allow from <IP_ROUTER> to any port 179 proto tcp
```

> [\!IMPORTANT]
> UFW filtra la entrada al **Nodo**. Si MetalLB asigna una IP externa a un servicio, el tráfico llega a la interfaz física del nodo. Asegúrate de que las reglas de `ufw allow` coincidan con los puertos que tus LoadBalancers están exponiendo si no usas rangos específicos.

---

#### Activación y Verificación

Una vez aplicadas las reglas, actívalo:

```bash
sudo ufw enable
```

Verifica el estado numerado para facilitar la lectura:

```bash
sudo ufw status numbered
```

#### Resumen de Puertos (Cheatsheet)

| Puerto | Protocolo | Servicio | Origen Permitido |
| --- | --- | --- | --- |
| **22** | TCP | SSH | Admin IP |
| **6443** | TCP | K8s API | Admin IP / Nodos |
| **9345** | TCP | RKE2/K3s Join | Nodos |
| **10250** | TCP | Kubelet | Nodos / Prometheus |
| **8472** | UDP | Cilium VXLAN | Nodos |
| **51871** | UDP | WireGuard | Nodos |
| **4240** | TCP | Cilium Health | Nodos |
| **Interfaces** | Any | `cilium_*` | **Any** (Interno) |

## Cilium WireGard

Es una funcionalidad nativa de Cilium que utiliza el protocolo **WireGuard** para encapsular y encriptar todo el tráfico de red que fluye entre los Pods de tu clúster Kubernetes.

* **Privacidad Total:** Asegura que si alguien intercepta el tráfico físico entre tus nodos, solo verá paquetes encriptados e ilegibles.
* **Rendimiento:** WireGuard es mucho más rápido y ligero que alternativas antiguas como IPsec, afectando mínimamente la latencia.
* **Transparencia:** No requiere cambios en tus aplicaciones. Tus servicios siguen comunicándose por HTTP/gRPC normal, pero Cilium cifra el cable automáticamente.
* **Zero Trust:** Cumple con requisitos de seguridad que exigen encriptación "en tránsito" dentro del centro de datos.

---

### Instalación y Activación

Esta implementación asume que ya tienes Cilium instalado vía Helm. Usaremos el flag `--reuse-values` para mantener tu configuración actual y solo "encender" la encriptación.

#### Paso A: Activar la Encriptación (Helm)

Este comando actualiza la configuración de Cilium en el clúster.

```bash
helm upgrade cilium cilium/cilium \
    --namespace kube-system \
    --reuse-values \
    --set encryption.enabled=true \
    --set encryption.type=wireguard
```

* `--reuse-values`: Vital para no borrar configuraciones previas (como tu IPAM o configuración de L7).
* `encryption.type=wireguard`: Especifica que usaremos el protocolo moderno WireGuard en lugar de IPsec.

#### Paso B: Aplicar los Cambios (Rollout)

Helm actualiza el ConfigMap, pero los agentes de Cilium que ya están corriendo necesitan reiniciarse para leer la nueva configuración y crear las interfaces de red `cilium_wg0`.

```bash
kubectl rollout restart ds/cilium -n kube-system
```

> [\!NOTE]
> Esto reiniciará los agentes de red en cada nodo. Puede haber una micro-interrupción de red de unos segundos mientras se levantan las interfaces de túnel.

---

### Verificación

Una vez que los Pods de Cilium estén en estado `Running`, verifica que la encriptación esté activa.

```bash
kubectl -n kube-system exec -ti ds/cilium -- cilium-dbg status | grep Encryption
```

Deberías ver una salida similar a esta:
```text
Encryption: WireGuard (UserKeys: 0, MaxSeqNum: 0/0)
```

Si dice `Disabled`, espera unos segundos más o revisa si los Pods se reiniciaron correctamente.

---

### Troubleshooting Rápido (Tips Extra)

Si algo falla, verifica estos puntos clave:

1. **El Puerto UDP:** Asegúrate de que el puerto **51871 UDP** (el puerto por defecto de WireGuard en Cilium) esté abierto en el firewall (UFW) entre todos los nodos.
* *Regla UFW:* `ufw allow 51871/udp`
2. **Kernel:** WireGuard funciona mejor si el módulo está nativo en el Kernel de Linux (Kernels 5.6+). Si usas una versión muy antigua, Cilium intentará usar una implementación en espacio de usuario (go-wireguard), que es mucho más lenta.
3. **MTU:** WireGuard añade una cabecera extra a los paquetes. Cilium suele manejar el MTU automáticamente, pero si tienes problemas de conexión, verifica que el MTU de la interfaz `cilium_wg0` sea menor que el de tu interfaz física (`eth0`).

## Tetragon















## Cilium Network Policy

## RBAC

cilium hubble enable
cilium hubble enable --ui
cilium hubble ui --port-forward 12000



HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
