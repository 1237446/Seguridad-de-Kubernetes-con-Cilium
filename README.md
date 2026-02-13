# Seguridad-de-Kubernetes-con-Cilium

Esta arquitectura implementa un modelo de **Defensa en Profundidad** utilizando el stack nativo de Cilium. Es fundamental entender que la seguridad no es una única barrera, sino una combinación de capas:

* **Host Firewall (eBPF):** Evolución de UFW que protege el nodo a nivel de kernel, filtrando el acceso externo (SSH, API) con mayor rendimiento.
* **Encriptación con WireGuard:** Crea túneles seguros y automáticos entre todos los nodos del clúster. Toda la comunicación entre Pods viaja cifrada por defecto, protegiendo los datos contra intercepción en la red física.
* **Tetragon (Runtime Security):** Monitorea la ejecución de procesos y el acceso a archivos en tiempo real. Detecta comportamientos anómalos dentro de los contenedores (ej. intentos de escalada de privilegios o ejecución de binarios sospechosos).
* **Políticas de Cilium (L3-L7):** Reglas de red inteligentes basadas en **Identidad** (labels) y no en IPs. Permite filtrar tráfico incluso a nivel de aplicación (HTTP/API).
* **Hubble (Observabilidad):** Proporciona visibilidad total del flujo de datos, permitiendo auditar y diagnosticar qué políticas están permitiendo o bloqueando el tráfico en tiempo real.

---

## Cilium Host Firewall (Seguridad a nivel de Nodo)

Cilium Host Firewall permite gestionar la seguridad de los nodos (hosts) utilizando **CiliumClusterwideNetworkPolicies (CCNP)**. A diferencia de UFW, Host Firewall no depende de iptables y permite usar selectores de etiquetas, entidades (como `remote-node` o `world`) y visibilidad avanzada.

> [!WARNING]
> **Host Firewall no está activo por defecto.** Si aplicas la política sin activar la función en el agente de Cilium, las reglas no se aplicarán.

#### Habilitar Host Firewall

Debes asegurarte de que Cilium tenga activada la opción `hostFirewall`. Puedes activarlo mediante Helm:

```bash
helm upgrade cilium cilium/cilium --namespace kube-system \
  --reuse-values \
  --set hostFirewall.enabled=true
```

#### Diferencia Clave: Entidades vs IPs

En UFW usabas variables como `$K8S_NODES_CIDR`. En Cilium usamos **Entidades**:

* **`host`**: El nodo local.
* **`remote-node`**: Cualquier otro nodo del clúster.
* **`cluster`**: Todos los Pods del clúster.
* **`world`**: Cualquier tráfico fuera del clúster.

### Implementación de la Política: `hfs-nodes-security`

Esta política centraliza todas las reglas de tu antigua guía de UFW, incluyendo las necesidades específicas de **RKE2**, **Ceph (Rook)** y **Bacula**.

#### Estructura y Acceso Administrativo

La política comienza seleccionando todos los nodos Linux y definiendo quién puede entrar vía SSH o API.

```yaml
apiVersion: "cilium.io/v2"
kind: CiliumClusterwideNetworkPolicy
metadata:
  name: "hfs-nodes-security"
spec:
  description: "Traslado de reglas UFW a Cilium Host Firewall"
  nodeSelector:
    matchLabels:
      kubernetes.io/os: linux # Aplica a todos los nodos Linux
  ingress:
    # --- ACCESO ADMINISTRATIVO ---
    - fromCIDRSet:
        - cidr: "172.16.8.208/32" # Tu IP de Admin específica
      toPorts:
        - ports:
            - port: "6443"
              protocol: TCP
            - port: "22"
              protocol: TCP

```

#### Infraestructura Kubernetes y Comunicación Interna

Reemplaza las reglas de VXLAN y WireGuard de UFW. Cilium identifica automáticamente a los otros nodos como `remote-node`.

```yaml
    # --- K8S API E INFRAESTRUCTURA (RKE2) ---
    - fromEntities:
        - cluster
        - host
      toPorts:
        - ports:
            - port: "6443" # API Server
              protocol: TCP
            - port: "9345" # RKE2 Supervisor
              protocol: TCP
            - port: "10250" # Kubelet
              protocol: TCP

    # --- CILIUM INTERNAL & ENCRIPTACIÓN ---
    - fromEntities:
        - remote-node
      toPorts:
        - ports:
            - port: "8472"  # VXLAN
              protocol: UDP
            - port: "4240"  # Health Checks
              protocol: TCP
            - port: "51871" # WireGuard
              protocol: UDP
            - port: "4244"  # Hubble Relay
              protocol: TCP

```

#### Tráfico de Almacenamiento (Ceph / Rook)

Dado que usas **Rook-Ceph** para la UNI, los nodos necesitan comunicarse intensamente para replicar datos. Esta sección reemplaza las aperturas manuales de puertos en UFW.

```yaml
    # --- CEPH INTERNAL STORAGE ---
    - fromEntities:
        - remote-node
      toPorts:
        - ports:
            - port: "6789" # Monitor
              protocol: TCP
            - port: "3300" # Messenger v2
              protocol: TCP
            - port: "6800" # OSDs Rango
              endPort: 7300
              protocol: TCP

```

#### Servicios Externos y Bacula

Aquí gestionamos cómo el mundo exterior ve tus servicios y cómo Bacula se comunica para los backups.

```yaml
    # --- NODEPORT Y SERVICIOS EXTERNOS ---
    - fromEntities:
        - world
      toPorts:
        - ports:
            - port: "30000"
              endPort: 32767
              protocol: TCP

    # --- BACULA Y TELEMETRÍA ---
    - fromEntities:
        - cluster
      toPorts:
        - ports:
            - port: "9101" # Bacula Director
              endPort: 9103 # FD y SD
              protocol: TCP
            - port: "9097" # Bacularis / API
              protocol: TCP

```

#### Reglas de Salida (Egress)

A diferencia de UFW donde poníamos `default allow outgoing`, en Cilium Host Firewall es mejor ser explícito, aunque aquí permitimos la salida general para evitar romper actualizaciones de sistema o consultas DNS.

```yaml
  egress:
    - toEntities:
        - cluster
        - world
        - host
        - remote-node

```

Si necesitas ver el estado de las políticas aplicadas en un nodo específico:

```bash
cilium policy wait
cilium bpf policy list

```

### Tabla Comparativa: UFW vs Cilium Host Firewall

| Función | UFW (Iptables) | Cilium Host Firewall (eBPF) |
| --- | --- | --- |
| **Rendimiento** | Decae con muchas reglas | Constante (O(1) lookup) |
| **Identidad** | Basada solo en IP | Basada en Entidades y Etiquetas |
| **Visibilidad** | Logs de kernel (dmesg) | Hubble (Flujos granulares) |
| **Gestión** | Manual por nodo | Declarativa (YAML) vía kubectl |

---

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

#### Ajuste Manual de MTU en Cilium

Primero, modificamos la configuración global de Cilium almacenada en el clúster:

```bash
kubectl edit cm -n kube-system cilium-config
```

Dentro de la sección `data:`, añadimos el valor del MTU (asegurándote de que esté entre comillas para que se trate como una cadena de texto):

```yaml
data:
  enable-wireguard: "true"
  mtu: "1375"  # <--- Esta es la línea que agregamos
  # ... otras configuraciones existentes
```

#### Paso B: Aplicar los Cambios (Rollout)

Helm actualiza el ConfigMap, pero los agentes de Cilium que ya están corriendo necesitan reiniciarse para leer la nueva configuración y crear las interfaces de red `cilium_wg0`.

```bash
kubectl rollout restart ds/cilium -n kube-system
```

Verificación del MTU

```bash
kubectl exec -n kube-system ds/cilium -- ip link show cilium_host

5: cilium_host@cilium_net: <BROADCAST,MULTICAST,NOARP,UP,LOWER_UP> mtu 1375 qdisc noqueue state UP mode DEFAULT group default qlen 1000
    link/ether 72:d2:b1:75:c6:c8 brd ff:ff:ff:ff:ff:ff
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
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon \
  -n kube-system
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

### Estructura Básica

Un archivo YAML de CNP se divide en tres partes clave:

1. **EndpointSelector:** ¿A quién protegemos? (El objetivo).
2. **Ingress:** ¿Quién puede entrar? (Tráfico entrante).
3. **Egress:** ¿A dónde pueden salir? (Tráfico saliente).

---

### Ejemplos Prácticos (Copy & Paste)

Aquí tienes 3 niveles de políticas, desde lo básico hasta lo avanzado.

#### Nivel 1: Aislamiento L3/L4 (El Muro Básico)

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

#### Nivel 2: Filtrado DNS / FQDN (Salida Controlada)

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

#### Nivel 3: Filtrado HTTP L7 (El Guardia Inteligente)

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

### Aplicación y Verificación

#### Paso A: Aplicar la política

Se aplica igual que cualquier manifiesto de Kubernetes:

```bash
kubectl apply -f mi-politica-cilium.yaml

```

#### Paso B: Verificar el estado

Cilium tiene su propio estado para las políticas. Verifica que esté cargada:

```bash
kubectl get cnp
# O para más detalle:
kubectl describe cnp mi-politica-cilium

```

#### Paso C: Auditoría con Hubble (La prueba real)

Si ya instalaste Hubble (guía anterior), úsalo para ver si tu política está bloqueando (`DROP`) o permitiendo (`FORWARD`) el tráfico en vivo:

```bash
# Ver tráfico denegado por política
hubble observe --verdict DROP

```

---

### ¡Cuidado! El Principio de "Default Deny"

Es vital entender esto: **En el momento en que aplicas UNA política** que selecciona a un Pod (ej. `app: database`), Cilium cambia automáticamente el modo de ese pod a **"Denegar todo por defecto"**.

* Si defines reglas de `Ingress`, se bloquea todo el tráfico entrante que no esté explícitamente permitido.
* Si defines reglas de `Egress`, se bloquea todo el tráfico saliente que no esté explícitamente permitido.

**Consejo de Seguridad:** Nunca apliques una política en Producción sin haberla probado antes en Desarrollo, o cortarás el servicio.

---

## Herramienta Recomendada: Network Policy Editor

Escribir YAML desde cero es propenso a errores. Cilium ofrece un editor visual gratuito que genera el YAML por ti:

* [Network Policy Editor](https://www.google.com/search?q=https://editor.cilium.io/)

Puedes dibujar visualmente "El frontend habla con el backend" y te dará el código listo para copiar.

## RBAC

El control de acceso basado en roles (**RBAC**), es el estándar de oro para decidir "quién puede hacer qué" dentro de tu clúster.

RBAC es vital para que, por ejemplo, el equipo de backups solo pueda gestionar recursos de **Bacula** sin tocar la configuración de red o los nodos.


### Conceptos Fundamentales de RBAC

RBAC se basa en cuatro objetos principales que se dividen en dos niveles:

| Objeto | Alcance | Descripción |
| --- | --- | --- |
| **Role** | Namespace | Define permisos (get, list, watch, create) dentro de un namespace específico. |
| **ClusterRole** | Todo el Clúster | Define permisos en todo el clúster o sobre objetos no segmentados (como Nodos). |
| **RoleBinding** | Namespace | Vincula un usuario o grupo a un `Role`. |
| **ClusterRoleBinding** | Todo el Clúster | Vincula un usuario o grupo a un `ClusterRole`. |

### Creación de un Rol (Role)

Supongamos que quieres que un usuario pueda ver y gestionar pods en el namespace de `bacula`.

**Archivo: `role-backup-manager.yaml**`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: bacula
  name: pod-manager
rules:
- apiGroups: [""] # "" indica el API core
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch", "update", "patch"]

```

## 2. Asignación del Rol (RoleBinding)

Ahora vinculamos ese rol a un usuario específico (en este caso, `adrian`).

**Archivo: `binding-backup-manager.yaml**`

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: adrian-pod-manager
  namespace: bacula
subjects:
- kind: User
  name: adrian
  apiGroup: rbac.authorization.k8s.io
roleRef:
  kind: Role
  name: pod-manager
  apiGroup: rbac.authorization.k8s.io

```

---

## 3. Roles a Nivel de Clúster (ClusterRole)

Si necesitas que alguien pueda ver los **Nodos** o las **CiliumNetworkPolicies** en todo el clúster, usas un `ClusterRole`.

**Ejemplo para auditoría de Red:**

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: network-auditor
rules:
- apiGroups: ["cilium.io"]
  resources: ["ciliumnetworkpolicies", "ciliumnodes"]
  verbs: ["get", "list", "watch"]

```

---

## 4. Comandos de Uso y Verificación

Una vez aplicados los archivos con `kubectl apply -f ...`, puedes verificar los permisos rápidamente:

### Verificar permisos actuales

¿Puedo yo (o un usuario específico) realizar una acción?

```bash
# ¿Puedo listar pods en el namespace bacula?
kubectl auth can-i list pods -n bacula

# ¿Puede el usuario 'adrian' borrar servicios?
kubectl auth can-i delete services -n bacula --as adrian

```

### Listar Roles y Vínculos

```bash
# Ver roles en un namespace
kubectl get roles -n bacula

# Ver quién tiene permisos en todo el clúster
kubectl get clusterrolebindings

```

---

## Buenas Prácticas (Principio de Menor Privilegio)

1. **Evita `cluster-admin`:** No des permisos de administrador global a menos que sea estrictamente necesario.
2. **Usa Namespaces:** Limita a los usuarios a sus áreas de trabajo (ej. `django-dev`, `backup-ops`).
3. **Audita con Hubble:** Como ya tienes **Hubble**, puedes ver qué identidades están intentando realizar llamadas a la API que son rechazadas por falta de permisos.
