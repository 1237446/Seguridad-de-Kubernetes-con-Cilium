# Seguridad-de-Kubernetes-con-Cilium
Esta guía detalla cómo asegurar los nodos de un clúster Kubernetes utilizando **UFW** (seguridad a nivel de host) en conjunto con **Cilium** (seguridad y red a nivel de Pod, con encriptación WireGuard).

Es vital distinguir las capas de seguridad para evitar cortes de servicio:

* **UFW (Host Firewall):** Protege el Sistema Operativo (Ubuntu/Debian). Su función es bloquear acceso SSH no autorizado y limitar qué puertos del nodo son visibles hacia internet o la red corporativa.
* **Cilium (CNI):** Gestiona la red interna de los contenedores. UFW **no** debe interferir con la comunicación interna de los Pods ni con las interfaces virtuales que Cilium crea (`cilium_host`, `cilium_vxlan`, `cilium_wg0`).

---

## UFW (Cortafuegos No Complicado)
UFW es una interfaz de gestión simplificada para el sistema de filtrado de paquetes de Linux (netfilter/iptables).

En Kubernetes, la gestión de redes es compleja porque K8s manipula dinámicamente las reglas de iptables para que los servicios y pods se comuniquen. Pero La utilidad principal de UFW en K8s no es gestionar la red de los contenedores, sino proteger al Nodo (el servidor host).

  * Seguridad del Host: Protege el sistema operativo base de accesos SSH no autorizados o escaneos de puertos externos.
  
  * Segmentación: Asegura que solo los puertos necesarios para el funcionamiento del clúster (API Server, Kubelet, Etcd) estén expuestos a las redes correctas.

### Pre-requisitos Críticos (Configuración del Sistema)

> [\!WARNING]
>  No saltes este paso. Si activas UFW sin habilitar el reenvío de paquetes, los Pods no podrán resolver DNS ni comunicarse entre sí.

#### A. Habilitar IP Forwarding

Kubernetes requiere que el tráfico pueda pasar a través del nodo hacia los contenedores.

Edita la configuración predeterminada de UFW:
```bash
sudo nano /etc/default/ufw
```

Busca y modifica la política de reenvío:
```bash
# Cambiar DROP por ACCEPT
DEFAULT_FORWARD_POLICY="ACCEPT"
```

Aplica los cambios (sin activar el firewall todavía):
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

#### Consideración Especial: MetalLB

UFW puede interferir con MetalLB dependiendo del modo:

* **Modo Layer 2 (ARP):** Generalmente funciona bien con las reglas anteriores. El tráfico llega al puerto del servicio y kube-proxy/cilium lo maneja.
* **Modo BGP:** Si configuras MetalLB con BGP, necesitas permitir el puerto **179 TCP** entre los nodos y tu router.
  
  ```bash
  sudo ufw allow from <IP_ROUTER> to any port 179 proto tcp
  ```

> [\!IMPORTANT]
> UFW filtra la entrada al **Nodo**. Si MetalLB asigna una IP externa a un servicio, el tráfico llega a la interfaz física del nodo. Asegúrate de que las reglas de `ufw allow` coincidan con los puertos que tus LoadBalancers están exponiendo si no usas rangos específicos.

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

### Troubleshooting Rápido (Tips Extra)

Si algo falla, verifica estos puntos clave:

1. **El Puerto UDP:** Asegúrate de que el puerto **51871 UDP** (el puerto por defecto de WireGuard en Cilium) esté abierto en el firewall (UFW) entre todos los nodos.
* *Regla UFW:* `ufw allow 51871/udp`
2. **Kernel:** WireGuard funciona mejor si el módulo está nativo en el Kernel de Linux (Kernels 5.6+). Si usas una versión muy antigua, Cilium intentará usar una implementación en espacio de usuario (go-wireguard), que es mucho más lenta.
3. **MTU:** WireGuard añade una cabecera extra a los paquetes. Cilium suele manejar el MTU automáticamente, pero si tienes problemas de conexión, verifica que el MTU de la interfaz `cilium_wg0` sea menor que el de tu interfaz física (`eth0`).

---

## Tetragon

Tetragon es una herramienta de **seguridad en tiempo real y observabilidad** basada en **eBPF**. A diferencia de los antivirus tradicionales o herramientas de seguridad que funcionan en el "espacio de usuario" (lento y vulnerable), Tetragon vive directamente en el **Kernel** de Linux.

* **Caja Negra del Clúster:** Registra *cada* proceso que se ejecuta, cada archivo que se toca y cada conexión de red que se abre, incluso si el contenedor dura milisegundos.
* **Prevención de Ataques:** Puede detener (matar) un proceso malicioso en el momento exacto en que intenta hacer algo prohibido (como abrir `/etc/shadow`), antes de que el daño ocurra.
* **Sin Puntos Ciegos:** Como usa eBPF, el malware no puede ocultarse modificando los logs del sistema, ya que Tetragon captura los datos antes de que lleguen a la aplicación.

### Instalación

Tetragon se instala generalmente como un DaemonSet (un agente en cada nodo). Usaremos el comando que proporcionaste, asumiendo que el repositorio de Cilium ya está añadido.

#### Paso A: Despliegue con Helm

Este comando instala los agentes de Tetragon en el espacio de nombres `kube-system`.

```bash
helm install tetragon cilium/tetragon -n kube-system
```

Al ejecutar ese comando:

 * Se despliega el **Tetragon Agent** en todos tus nodos.
 * El agente carga programas **eBPF** en el Kernel del host.
 * Empieza a escuchar eventos del sistema (syscalls) silenciosamente.
   
> [\!NOTE]
> Si recibes un error de "repo not found", asegúrate de ejecutar antes `helm repo add cilium https://helm.cilium.io` y `helm repo update`.

#### Paso B: Verificación y Uso

A diferencia de Cilium, Tetragon no suele tener un "status" binario de encendido/apagado, sino que se verifica viendo si está "escuchando".

```bash
kubectl get pods -n kube-system | grep tetragon
```
```bash
tetragon-48fh7                                          2/2     Running     0               29s
tetragon-9mrmf                                          2/2     Running     0               29s
tetragon-dzms4                                          2/2     Running     0               29s
tetragon-nqjz9                                          2/2     Running     0               29s
tetragon-operator-5c67c579b7-k8tmm                      1/1     Running     0               29s
tetragon-rjdrf                                          2/2     Running     0               29s
tetragon-sbmdk                                          2/2     Running     0               29s
```

#### Ver la "Magia" (Logs en tiempo real)

Para ver qué está pasando en tu clúster *ahora mismo*:

```bash
kubectl exec -it -n kube-system ds/tetragon -c tetragon -- tetra getevents -o compact
```
```bash
🚀 process rook-ceph/rook-ceph-operator-5cfc4646c7-6x4dg /usr/bin/ceph -s /usr/bin/ceph status --format json --connect-timeout=15 --cluster=rook-ceph --conf=/var/lib/rook/rook-ceph/rook-ceph.config --name=client.admin --keyring=/var/lib/rook/rook-ceph/client.admin.keyring 
💥 exit    rook-ceph/rook-ceph-operator-5cfc4646c7-6x4dg /usr/bin/ceph -s /usr/bin/ceph status --format json --connect-timeout=15 --cluster=rook-ceph --conf=/var/lib/rook/rook-ceph/rook-ceph.config --name=client.admin --keyring=/var/lib/rook/rook-ceph/client.admin.keyring 0 
🚀 process rook-ceph/rook-ceph-operator-5cfc4646c7-6x4dg /usr/bin/ceph -s /usr/bin/ceph versions --connect-timeout=15 --cluster=rook-ceph --conf=/var/lib/rook/rook-ceph/rook-ceph.config --name=client.admin --keyring=/var/lib/rook/rook-ceph/client.admin.keyring --format json 
💥 exit    rook-ceph/rook-ceph-operator-5cfc4646c7-6x4dg /usr/bin/ceph -s /usr/bin/ceph versions --connect-timeout=15 --cluster=rook-ceph --conf=/var/lib/rook/rook-ceph/rook-ceph.config --name=client.admin --keyring=/var/lib/rook/rook-ceph/client.admin.keyring --format json 0
```

* **Lo que verás:** Un flujo rápido de datos. Cada vez que alguien hace un `curl`, abre un archivo o ejecuta un comando en *cualquier* pod, aparecerá ahí.

### El siguiente nivel: TracingPolicy (Bloqueo Activo)

Instalarlo es solo el primer paso. El verdadero poder de Tetragon reside en las **TracingPolicies** (Políticas de Rastreo).

Por defecto, Tetragon solo *observa*. Para bloquear ataques, aplicamos archivos YAML (CRDs) que definen qué actividades están prohibidas. Cuando se viola una regla, Tetragon envía una señal `SIGKILL` desde el Kernel, matando el proceso malicioso instantáneamente antes de que termine de ejecutarse.

Aquí tienes 3 políticas esenciales basadas en tus archivos para endurecer el clúster:

#### Bloqueo de Herramientas de Red y Gestores de Paquetes

**Archivo:** `block-net-tools-exec.yaml`

Esta política es vital para evitar la técnica de "Living off the Land" (usar herramientas ya instaladas para atacar).

* **Qué hace:** Prohíbe ejecutar `curl`, `wget`, `nc` (usados para descargar malware o exfiltrar datos) y bloquea gestores como `apt`, `apk` o `pip` (para evitar instalar herramientas de hacking).
* **Inteligencia:** Incluye una **Lista Blanca (Excepciones)** para que pods de infraestructura crítica (como `rook-ceph`) sigan funcionando sin problemas.

  ```yaml
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
  metadata:
    name: "block-net-tools-exec"
  spec:
    # Excepciones: Permitir que Rook-Ceph y otros pods autorizados funcionen
    podSelector:
      matchExpressions:
      - key: allow-net-tools
        operator: NotIn
        values:
        - "true"
      - key: app
        operator: NotIn
        values:
        - "rook-ceph-rgw"
        - "rook-ceph-mgr"
        - "rook-ceph-mon"
        - "rook-ceph-osd"
  
    # Reglas
    kprobes:
    - call: "sys_execve"
      syscall: true
      args:
      - index: 0
        type: "string"
      selectors:
      - matchArgs:      
        - index: 0
          operator: "Equal"
          values:
          # --- Herramientas de Transferencia ---
          - "/usr/bin/curl"     # bajar archivos
          - "/bin/curl"         # bajar archivos
          - "/usr/bin/wget"     # bajar archivos
          - "/bin/wget"         # bajar archivos
          - "/usr/bin/nc"       # red
          - "/bin/nc"           # red
          - "/usr/bin/ncat"     # red
          
          # --- Gestores de Paquetes (Debian/Ubuntu/Alpine/RHEL) ---
          - "/usr/bin/apt"      # Gestor de paquetes Debian/Ubuntu
          - "/bin/apt"          # Gestor de paquetes Debian/Ubuntu
          - "/usr/bin/apt-get"  # Gestor de paquetes Debian/Ubuntu
          - "/bin/apt-get"      # Gestor de paquetes Debian/Ubuntu
          - "/usr/bin/dpkg"     # El motor detrás de apt
          - "/bin/dpkg"         # El motor detrás de apt
          - "/sbin/apk"         # Gestor de paquetes Alpine
          - "/bin/apk"          # Gestor de paquetes Alpine
          - "/usr/bin/yum"      # Gestor de paquetes RHEL/CentOS
          - "/usr/bin/dnf"      # Gestor de paquetes Fedora/RHEL modernos
          - "/usr/bin/pip"      # Python Package Installer (riesgo alto)
          - "/usr/bin/npm"      # Node Package Manager (riesgo alto)
        matchActions:
        - action: Sigkill
  ```

#### Inmutabilidad del Sistema (Anti-Tampering)

**Archivo:** `block-system-writes.yaml`

Si un atacante logra entrar, intentará instalar rootkits o modificar binarios del sistema. Esta política congela las carpetas críticas.

* **Qué hace:** Intercepta la llamada `security_file_permission`. Si alguien intenta **escribir** (`MAY_WRITE = 2`) en `/bin`, `/usr/bin`, `/boot`, etc., es eliminado.

  ```yaml
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
  metadata:
    name: "enforce-immutable-system"
  spec:
  
    # Reglas
    kprobes:
    - call: "security_file_permission"
      syscall: false
      return: true
      args:
      - index: 0
        type: "file" 
      - index: 1
        type: "int"
      returnArg:
        index: 0
        type: "int"
      returnArgAction: "Post"
      selectors:
      # ---------------------------------------------------------
      # BLOQUEO DE MODIFICACIONES DEL SISTEMA (Anti-Tampering)
      # Mata cualquier proceso que intente escribir en carpetas de sistema.
      # ---------------------------------------------------------
      - matchArgs:      
        - index: 0
          operator: "Prefix"
          values:
          - "/bin"
          - "/usr/bin"
          - "/usr/sbin"
          - "/sbin"
          - "/boot"
          - "/lib"
        - index: 1
          operator: "Equal"
          values:
          - "2" # 2 = MAY_WRITE
        matchActions:
        - action: Sigkill # <--- AHORA BLOQUEA (Mata el proceso)
  ```

#### Protección de Credenciales (/etc/shadow)

**Archivo:** `secure-shadow-sudo-deny.yaml`

El archivo `/etc/shadow` contiene los hashes de las contraseñas. Nadie debería leerlo excepto el sistema de login y backups autorizados.

* **Qué hace:** Bloquea cualquier lectura (`MAY_READ = 4`) a `/etc/shadow`.
* **Lista Blanca (Binaries):** Permite explícitamente procesos legítimos como `sshd` (para que puedas entrar) y  `sudo`.

  ```yaml
  apiVersion: cilium.io/v1alpha1
  kind: TracingPolicy
  metadata:
    name: "secure-shadow-ssh-safe"
  spec:
  
    # Reglas
    kprobes:
    - call: "security_file_permission"
      syscall: false
      return: true
      args:
      - index: 0
        type: "file" 
      - index: 1
        type: "int"
      returnArg:
        index: 0
        type: "int"
      returnArgAction: "Post"
      selectors:
      - matchArgs:      
        - index: 0
          operator: "Equal"
          values:
          - "/etc/shadow"
        - index: 1
          operator: "Equal"
          values:
          - "4" # MAY_READ
        
        # =======================================================
        # LISTA BLANCA (Binarios Autorizados)
        # =======================================================
        matchBinaries:
        - operator: "NotIn"
          values:
          # Administración del Sistema (SSH/Sudo)
          - "/usr/bin/sudo"       # Permitir sudo
          - "/usr/sbin/sshd"      # Permitir Servidor SSH <--- ESTO FALTABA
          - "/usr/bin/ssh"        # Cliente SSH (a veces necesario)
          - "/usr/bin/login"      # Login de consola local
          - "/usr/bin/passwd"     # Cambio de contraseña
        
        # =======================================================
        # ACCIÓN: MATAR AL RESTO
        # =======================================================
        matchActions:
        - action: Sigkill
  ```

#### Cómo aplicar y probar

**Aplicar las políticas:**
Guarda los YAML y aplícalos como cualquier objeto de Kubernetes:
```bash
kubectl apply -f block-net-tools-exec.yaml
kubectl apply -f block-system-writes.yaml
kubectl apply -f secure-shadow-sudo-deny.yaml
```

**Prueba de Fuego (Verificación):**
Intenta ejecutar un curl desde un pod cualquiera:
```bash
kubectl exec -it mi-pod -- curl google.com
```
**Resultado esperado:**
```text
command terminated with exit code 137
```

*(El código 137 indica `SIGKILL`. El comando ni siquiera llegó a ejecutarse; Tetragon lo mató).*
**Ver el Log del Asesinato:**
En los logs de Tetragon verás el evento con el emoji 💥 y la acción `SIGKILL`.


Aquí tienes la guía para **Hubble**, el componente de observabilidad de Cilium, siguiendo el mismo formato directo y práctico.

---

## Observabilidad Visual con Hubble

Hubble es el "telescopio" de Cilium. Es una plataforma de observabilidad distribuida que se monta sobre eBPF para ver exactamente cómo fluyen los paquetes de red dentro de tu clúster Kubernetes.

 * **Mapa de Servicios:** Dibuja automáticamente un mapa visual de quién habla con quién (Services, Pods, World).
 * **Depuración de Red:** Te permite ver si un paquete fue **DROP** (bloqueado por política) o **FORWARD** (permitido) en tiempo real, sin usar `tcpdump`.
 * **Visibilidad L7:** Puede inspeccionar tráfico HTTP, DNS y Kafka (ej. ver qué URL exacta dio un error 500).

### Instalación del Cliente CLI

Para interactuar con Hubble desde tu terminal (sin usar la interfaz gráfica), necesitas el binario `hubble`. Los comandos que proporcionaste hacen lo siguiente: detectan tu arquitectura (Intel/AMD vs ARM), descargan la última versión estable, verifican la integridad (checksum) y lo instalan en tu sistema.

#### Paso A: Descargar e Instalar

Copia y pega este bloque completo en tu terminal:

```bash
# 1. Detectar versión estable y arquitectura
HUBBLE_VERSION=$(curl -s https://raw.githubusercontent.com/cilium/hubble/master/stable.txt)
HUBBLE_ARCH=amd64
if [ "$(uname -m)" = "aarch64" ]; then HUBBLE_ARCH=arm64; fi
# 2. Descargar binario y archivo de verificación
curl -L --fail --remote-name-all https://github.com/cilium/hubble/releases/download/$HUBBLE_VERSION/hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
# 3. Verificar que la descarga es segura (Checksum)
sha256sum --check hubble-linux-${HUBBLE_ARCH}.tar.gz.sha256sum
# 4. Descomprimir e instalar en /usr/local/bin
sudo tar xzvfC hubble-linux-${HUBBLE_ARCH}.tar.gz /usr/local/bin
# 5. Limpiar archivos temporales
rm hubble-linux-${HUBBLE_ARCH}.tar.gz{,.sha256sum}
```

#### Paso B: Activar el Backend (Relay)

Este comando despliega **Hubble Relay** y configura los certificados TLS necesarios para que funcione de forma segura.

```bash
cilium hubble enable
```
```bash
cilium status

    /¯¯\
 /¯¯\__/¯¯\    Cilium:             OK
 \__/¯¯\__/    Operator:           OK
 /¯¯\__/¯¯\    Envoy DaemonSet:    OK
 \__/¯¯\__/    Hubble Relay:       OK
    \__/       ClusterMesh:        disabled

DaemonSet              cilium                   Desired: 6, Ready: 6/6, Available: 6/6
DaemonSet              cilium-envoy             Desired: 6, Ready: 6/6, Available: 6/6
Deployment             cilium-operator          Desired: 1, Ready: 1/1, Available: 1/1
Deployment             hubble-relay             Desired: 1, Ready: 1/1, Available: 1/1
Deployment             hubble-ui                Desired: 1, Ready: 1/1, Available: 1/1
Containers:            cilium                   Running: 6
                       cilium-envoy             Running: 6
                       cilium-operator          Running: 1
                       clustermesh-apiserver    
                       hubble-relay             Running: 1
                       hubble-ui                Running: 1
Cluster Pods:          53/53 managed by Cilium
Helm chart version:    1.18.5
Image versions         cilium             quay.io/cilium/cilium:v1.18.5@sha256:2c92f...
                       cilium-envoy       quay.io/cilium/cilium-envoy:v1.34.12-17653...
                       cilium-operator    quay.io/cilium/operator-generic:v1.18.5@sh...
                       hubble-relay       quay.io/cilium/hubble-relay:v1.18.5@sha256...
                       hubble-ui          quay.io/cilium/hubble-ui-backend:v0.13.3@s...
                       hubble-ui          quay.io/cilium/hubble-ui:v0.13.3@sha256:66...
```

* **¿Qué hace?** Habilita la exportación de eventos de red desde los nodos hacia un servicio centralizado (Relay).

#### Paso C: Activar la Interfaz Gráfica (UI)

Si quieres ver el mapa visual (muy recomendado), activa el dashboard web:

```bash
cilium hubble enable --ui
```

* **Resultado:** Desplegará un pod `hubble-ui` en el namespace `kube-system`.

  ```bash
  kubectl get pods -n kube-system | grep hubble
  
  hubble-relay-54774bdddb-zv2lw                           1/1     Running     0               7m
  hubble-ui-576dcd986f-7c5bm                              2/2     Running     0               4m
  ```

### Acceso y Uso

Una vez desplegado, tienes dos formas de ver los datos: vía web (UI) o vía terminal (CLI).

#### Ver el Mapa Visual (Recomendado)

Este comando crea un túnel seguro desde tu máquina local hacia el clúster para abrir la web.

```bash
cilium hubble ui --port-forward 12000
```

 * **Acción:** Abrirá automáticamente tu navegador en `http://localhost:12000`.
 * **Lo que verás:** Un mapa interactivo donde puedes seleccionar un Namespace y ver las líneas de comunicación entre tus microservicios. Las líneas **rojas** indican tráfico bloqueado.


### Troubleshooting Rápido

Si la UI no carga o no ves datos:

 * **Estado de los Pods:** Verifica que todo esté en verde.
   ```bash
   kubectl get pods -n kube-system -l k8s-app=hubble-ui
   kubectl get pods -n kube-system -l k8s-app=hubble-relay
   ```
 
 * **Firewall:** Si usas UFW (como configuramos antes), asegúrate de que el **Hubble Relay** pueda hablar con los nodos. El puerto de Hubble suele ser el **4244 (Server)** y **4245 (Relay)** TCP.
> [\!TIP]
> *Si seguiste la guía de UFW anterior, estos puertos ya deberían estar permitidos internamente.*

---

## Cilium Network Policy

Mientras que las *Network Policies* nativas de Kubernetes son como un portero básico (solo miran IP y Puerto), las **Cilium Network Policies** son como un agente de aduanas inteligente: pueden inspeccionar el contenido del paquete (HTTP, DNS, API calls) y entienden identidades lógicas. El CRD de Cilium permite:

 * **Filtrado de Capa 7 (L7):** Permitir `GET /public` pero bloquear `POST /admin`.
 * **Filtrado por DNS (FQDN):** Permitir salida a `google.com` sin saber sus IPs (que cambian constantemente).
 * **Entidades Lógicas:** Usar palabras clave como `world`, `host`, `cluster` en lugar de rangos de IP (CIDRs).

---

## 2. Estructura Básica

Un archivo YAML de CNP se divide en tres partes clave:

1. **EndpointSelector:** ¿A quién protegemos? (El objetivo).
2. **Ingress:** ¿Quién puede entrar? (Tráfico entrante).
3. **Egress:** ¿A dónde pueden salir? (Tráfico saliente).

---

## 3. Ejemplos Prácticos (Copy & Paste)

Aquí tienes 3 niveles de políticas, desde lo básico hasta lo avanzado.

### Nivel 1: Aislamiento L3/L4 (El Muro Básico)

*Caso de uso:* Proteger una base de datos. Solo el backend puede hablarle en el puerto 3306.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: "db-access-control"
spec:
  endpointSelector:
    matchLabels:
      app: database  # 1. Protegemos al pod 'database'
  ingress:
  - fromEndpoints:
    - matchLabels:
        app: backend # 2. Solo el 'backend' puede entrar
    toPorts:
    - ports:
      - port: "3306"
        protocol: TCP

```

### Nivel 2: Filtrado DNS / FQDN (Salida Controlada)

*Caso de uso:* Un pod necesita descargar actualizaciones de `github.com`, pero no quieres que tenga acceso a todo internet para evitar exfiltración de datos.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: "allow-github-only"
spec:
  endpointSelector:
    matchLabels:
      app: build-worker
  egress:
  - toFQDNs:
    - matchName: "github.com"      # Acceso exacto
    - matchPattern: "*.githubusercontent.com" # Acceso con comodín
    toPorts:
    - ports:
      - port: "443"
        protocol: TCP
  # IMPORTANTE: Permitir consultas DNS (puerto 53) para resolver esos nombres
  - toEndpoints:
    - matchLabels:
        k8s-app: kube-dns
        io.kubernetes.pod.namespace: kube-system
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP

```

### Nivel 3: Filtrado HTTP L7 (El Guardia Inteligente)

*Caso de uso:* Tienes una API pública. Quieres que el mundo vea los datos (`GET`), pero que nadie pueda borrarlos (`DELETE`) excepto una IP de administración interna.

```yaml
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: "secure-api-l7"
spec:
  endpointSelector:
    matchLabels:
      app: my-api
  ingress:
  - fromEntities:
    - world # Todo internet
    toPorts:
    - ports:
      - port: "80"
        protocol: TCP
      rules:
        http:
        - method: "GET"
          path: "/public/.*" # Permitir ver datos públicos
        # Todo lo demás (POST, DELETE, /admin) será denegado por defecto

```

---

## 4. Aplicación y Verificación

### Paso A: Aplicar la política

Se aplica igual que cualquier manifiesto de Kubernetes:

```bash
kubectl apply -f mi-politica-cilium.yaml

```

### Paso B: Verificar el estado

Cilium tiene su propio estado para las políticas. Verifica que esté cargada:

```bash
kubectl get cnp
# O para más detalle:
kubectl describe cnp mi-politica-cilium

```

### Paso C: Auditoría con Hubble (La prueba real)

Si ya instalaste Hubble (guía anterior), úsalo para ver si tu política está bloqueando (`DROP`) o permitiendo (`FORWARD`) el tráfico en vivo:

```bash
# Ver tráfico denegado por política
hubble observe --verdict DROP

```

---

## 5. ¡Cuidado! El Principio de "Default Deny"

Es vital entender esto: **En el momento en que aplicas UNA política** que selecciona a un Pod (ej. `app: database`), Cilium cambia automáticamente el modo de ese pod a **"Denegar todo por defecto"**.

* Si defines reglas de `Ingress`, se bloquea todo el tráfico entrante que no esté explícitamente permitido.
* Si defines reglas de `Egress`, se bloquea todo el tráfico saliente que no esté explícitamente permitido.

**Consejo de Seguridad:** Nunca apliques una política en Producción sin haberla probado antes en Desarrollo, o cortarás el servicio.

---

## 💡 Herramienta Recomendada: Network Policy Editor

Escribir YAML desde cero es propenso a errores. Cilium ofrece un editor visual gratuito que genera el YAML por ti:

* [Network Policy Editor](https://www.google.com/search?q=https://editor.cilium.io/)

Puedes dibujar visualmente "El frontend habla con el backend" y te dará el código listo para copiar.

## RBAC
