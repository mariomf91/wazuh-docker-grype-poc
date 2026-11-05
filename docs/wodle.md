# Colector de Docker como wodle

El agente Wazuh de Windows ejecuta el colector con un wodle `command`. No hay que lanzarlo, pararlo ni relanzarlo cada hora: el agente lo arranca con el servicio.

## Cómo funciona

El wodle lanza [collector-windows-wodle.ps1](../windows/collector-windows-wodle.ps1) cada 10 s. En cada ejecución el script:

1. Lee su punto de partida del fichero de estado (`<LogPath>.state.json`).
2. Pregunta a Docker su ID y su reloj (`docker info`) y calcula la ventana de eventos con ese reloj, el mismo que sella los eventos.
3. Pide `docker events --since <último> --until <ahora>`. Con `--until` en el pasado el comando vuelca el histórico de la ventana y termina.
4. Escribe cada evento nuevo en el JSONL, uno por línea, y guarda el estado tras cada uno.
5. Termina. El agente lee el JSONL con `<localfile>`.

Así no se repiten ni se pierden eventos entre ejecuciones, y no hay un proceso largo que vigilar.

**Formato de cada línea.** Igual que el colector original: el evento Docker completo bajo `docker`, y para `pull` de imagen y `create`/`start` de contenedor un bloque `poc` con `image_ref`, `platform`, `image_id`, `repo_digest`, `identity_kind`, `identity_status`, `engine_id`, `observed_at`, `event_type` y `action`. Tope de 5500 bytes por línea: un evento mayor se omite con un aviso, nunca se trunca.

**Una ejecución a la vez.** Un mutex (`Global\WazuhDockerEventsCollector`) impide que dos ejecuciones escriban a la vez. La documentación oficial del wodle `command` no dice qué pasa si una ejecución dura más que el intervalo; el mutex cubre ese caso.

**Avisos del propio colector.** Líneas con `integration: poc_collector`:

| `status` | Cuándo |
|---|---|
| `error` | Docker no responde. Se avisa una sola vez al empezar el fallo, no en cada ejecución. |
| `recovered` | Docker vuelve a responder tras un `error`. |
| `gap` | Pasó más de `MaxWindowSeconds` desde la última lectura (agente parado, por ejemplo): se omiten los eventos más antiguos. |

**Conexión.** Usa el named pipe del engine (`-H npipe:////./pipe/dockerDesktopLinuxEngine`), no el contexto de Docker del usuario, para poder correr como LocalSystem. No se expone la API de Docker por TCP.

**Primera ejecución.** Sin estado, empieza en el instante actual del engine (`-LookbackSeconds 0`): no recoge eventos anteriores.

### Diferencias con el colector original

- Ventana corta en lugar de una captura continua de hasta 3600 s, y estado entre ejecuciones.
- Mutex y aviso único de errores.
- En Windows PowerShell 5.1, con `$ErrorActionPreference = 'Stop'`, el stderr de un ejecutable nativo se convierte en excepción aunque se redirija con `2>$null`. El colector original tiene ese fallo latente; este lo evita envolviendo las llamadas en `Invoke-Docker`, que comprueba el código de salida.
- El original se conserva en [windows/original](../windows/original/collector-windows.ps1) como referencia.

## Parámetros

| Parámetro | Por defecto | Qué hace |
|---|---|---|
| `-DockerHost` | `npipe:////./pipe/dockerDesktopLinuxEngine` | Endpoint del engine. |
| `-LogPath` | `C:\WazuhPoC\runtime\docker-events.jsonl` | JSONL de salida. Debe coincidir con el `localfile`. |
| `-StatePath` | `<LogPath>.state.json` | Fichero de estado. |
| `-LookbackSeconds` | `0` | Solo en la primera ejecución: segundos hacia atrás a leer (0-3600). |
| `-MaxWindowSeconds` | `600` | Ventana máxima por ejecución (10-86400); más allá se avisa con `gap`. |

## Instalación

Requisitos: Docker Desktop con engine Linux en marcha, agente Wazuh instalado y la carpeta de salida creada.

En un PowerShell **como administrador**:

```powershell
# 1. Script en una carpeta que solo puedan modificar administradores y SYSTEM
$dest = 'C:\WazuhPoC\wodle'
New-Item -ItemType Directory -Force -Path $dest, 'C:\WazuhPoC\runtime' | Out-Null
Copy-Item .\windows\collector-windows-wodle.ps1 $dest
icacls $dest /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-32-545:(OI)(CI)RX'

# 2. Copia del ossec.conf del agente
$conf = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
Copy-Item $conf "$conf.antes-wodle"
```

3. Editar `ossec.conf` e incorporar, dentro del `<ossec_config>` existente, los bloques de [localfile.ejemplo.xml](../windows/localfile.ejemplo.xml) y [wodle.ejemplo.xml](../windows/wodle.ejemplo.xml). Las rutas del script y de `-LogPath` deben coincidir con las reales. Si el agente ya tiene un `localfile` para ese JSONL, no se repite.

4. Reiniciar el agente:

```powershell
Restart-Service WazuhSvc
```

`-ExecutionPolicy Bypass` va en el comando porque LocalSystem no tiene política definida y Windows 11 la trata como `Restricted`. No se cambia ninguna política del equipo.

### Comprobar

En `ossec.log` del agente (leerlo requiere administrador) debe verse `Module command:docker-events started` y, cada 10 s, `Starting command 'docker-events'`, sin avisos de código de salida.

```powershell
Get-Content 'C:\Program Files (x86)\ossec-agent\ossec.log' -Tail 50 | Select-String 'docker-events'
Get-Content 'C:\WazuhPoC\runtime\docker-events.jsonl.state.json'
docker --context desktop-linux pull alpine:3.21
```

El fichero de estado lo escribe LocalSystem: si existe y se actualiza, el wodle funciona. Tras el `pull` aparece una línea nueva con `docker.Action = pull` y `poc.identity_status = ok` en unos 10 s como máximo.

### Marcha atrás

Restaurar la copia y reiniciar el agente:

```powershell
Copy-Item "$conf.antes-wodle" $conf -Force
Restart-Service WazuhSvc
```

Para pausar el wodle sin quitar el bloque, la [documentación oficial](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html) ofrece la opción `disabled`: poner `<disabled>yes</disabled>` y reiniciar el agente. No se ha probado en este laboratorio.

No ejecutar el colector original a la vez que el wodle sobre el mismo archivo: duplicaría los eventos.

## Pruebas realizadas (5 nov 2026)

Windows 11 Pro, Docker Desktop 4.93.0, Engine 29.8.1, Windows PowerShell 5.1.

Con el script lanzado a mano y un log temporal:

- Primera ejecución sin estado: 0 eventos, fija el punto de partida.
- `pull` y `create` de una imagen: 2 eventos con digest y `identity_status = ok`; una ejecución repetida: 0.
- Claves de la línea idénticas a las del colector original.
- Docker inalcanzable (pipe inexistente): un solo aviso `error`, sin repetirlo en la segunda ejecución; al volver, un aviso `recovered`.
- Mutex ocupado por otro proceso: la ejecución se omite.

Como wodle, ejecutado por el agente como LocalSystem:

- Se lanza cada 10 s sin avisos; el fichero de estado lo escribe SYSTEM.
- Un `pull` de imagen llegó al JSONL con identidad `ok`, generó la alerta 100261 a los 4 s y el resumen de Grype a los 11 s (una medición, manager en modo stateful).

El aviso `gap` no se ha provocado en las pruebas.

## Límites conocidos

- **Aviso confuso.** La regla 100264 (`manager/comun/poc_rules.xml`) salta con cualquier línea `integration: poc_collector`, también con `recovered` y `gap`. Tras una caída de Docker habría dos alertas de «fallo del colector». Pendiente: emitir `recovered` con otro nombre de integración o ajustar la regla.
- **Sin rotación.** El JSONL crece sin límite; la rotación y la supervisión del archivo quedan fuera de la PoC.
- **Latencia.** Hasta un intervalo (10 s) entre el evento y su lectura, más lo que tarde el análisis.
- **Eventos antiguos.** Tras una pausa mayor que `MaxWindowSeconds` no se recuperan los eventos anteriores.
- **Solo Docker Desktop con engine Linux sobre WSL2 en Windows 11.** Podman y macOS no están validados.
