# Guía de laboratorio

## Alcance y requisitos comprobados

El ensayo se hizo con Docker Desktop 4.93.0 / Engine 29.8.1, engine Linux amd64 sobre WSL2, y manager Wazuh 4.14.8 (identificado como rc2) dentro de Docker. Son versiones observadas, no una matriz de compatibilidad certificada.

El colector corre como wodle `command` del agente Windows (LocalSystem); ver [wodle.md](wodle.md). Tampoco se ha validado Podman ni la recogida en macOS con estos scripts.

El manager necesita Python con `sqlite3` y `fcntl`, su socket local de Wazuh, acceso de red al registro y Grype Linux 0.121.0. La configuración rechaza otra versión de Grype. El binario, su base de vulnerabilidades y las imágenes se obtienen por separado.

La configuración limita el escáner a `docker.io/library/alpine`, `docker.io/library/nginx` y `docker.io/library/busybox`. Solo se probó el escaneo de Alpine; Nginx se usó también para inspeccionar la identidad. Las imágenes privadas o construidas solo en el endpoint requieren otro diseño de acceso y transferencia y no están cubiertas.

## Windows: colector y localfile

El agente ejecuta [collector-windows-wodle.ps1](../windows/collector-windows-wodle.ps1) cada 10 s; cada ejecución añade al JSONL los eventos nuevos de Docker y termina. Instalación, parámetros, seguridad y límites: [wodle.md](wodle.md).

Incorporar [localfile.ejemplo.xml](../windows/localfile.ejemplo.xml) dentro del `ossec_config` del agente existente, usando exactamente la misma ruta que `-LogPath`, y reiniciar el agente después de respaldar y revisar la configuración. El ejemplo lee JSONL; no es un `ossec.conf` completo.

El colector conserva el evento Docker original bajo `docker` y añade metadatos bajo `poc`. Enriquece el `pull` de imagen y el `create`/`start` de contenedor; el stream incluye otros eventos, que también se escriben. El análisis lo dispara únicamente un `pull` fuera de la lista CDB; `create` y `start` tienen alertas de política, sin análisis en esta versión.

El colector continuo original ([windows/original](../windows/original/collector-windows.ps1)) se conserva como referencia: abre el stream con `--since` del inicio de cada conexión, reconecta tras 5 s y no recupera el hueco entre conexiones. No ejecutar dos colectores sobre el mismo archivo.

## Manager: ubicación de archivos

El repositorio separa los archivos para facilitar la revisión. Al instalarlos, los scripts y sus JSON deben quedar con los nombres y rutas siguientes.

| Origen en el repositorio | Destino Linux |
|---|---|
| manager/comun/custom-grype | /var/ossec/integrations/custom-grype |
| manager/comun/grype-poc.yaml | /var/ossec/integrations/grype-poc.yaml |
| manager/comun/poc_rules.xml | /var/ossec/etc/rules/poc_rules.xml |
| manager/comun/poc-imagenes-permitidas | /var/ossec/etc/lists/poc-imagenes-permitidas |
| manager/stateless/custom-grype.json | /var/ossec/integrations/custom-grype.json |
| manager/stateful/custom-grype-stateful | /var/ossec/integrations/custom-grype-stateful |
| manager/stateful/grype_state_store.py | /var/ossec/integrations/grype_state_store.py |
| manager/stateful/custom-grype-stateful.json | /var/ossec/integrations/custom-grype-stateful.json |
| manager/stateful/poc_stateful_rules.xml | /var/ossec/etc/rules/poc_stateful_rules.xml |

Para stateless bastan los archivos comunes y su JSON. Para stateful hacen falta los comunes y los cuatro archivos stateful de la tabla; `custom-grype` se reutiliza por importación y no se activa además como integración.

Usar los permisos de integración indicados por Wazuh: script ejecutable `root:wazuh`, modo 750. El módulo Python debe ser legible por ese usuario y grupo. Los JSON y el YAML pueden usar `root:wazuh`, modo 640. Comprobar que existe el intérprete de las shebang: `/var/ossec/framework/python/bin/python3`.

Preparar las rutas indicadas en los JSON: binario `/var/ossec/integrations/grype-poc-bin/grype`, caché `/var/ossec/queue/grype-poc/db` y directorios de lock y estado. Estos últimos deben ser escribibles por el usuario efectivo de Integrator. Para stateful: `/var/ossec/queue/grype-poc-stateful`. Si el manager es un contenedor, revisar la persistencia del directorio `queue`.

Conservar los bytes de `custom-grype` y `grype-poc.yaml`. Sus SHA256 están fijados en `custom-grype-stateful.json`. Cambiar saltos de línea o editar el perfil rompe la comprobación; revisar explícitamente el cambio y el ámbito del estado antes de actualizar los hashes. Por eso el repositorio desactiva la conversión de saltos de línea (`.gitattributes`).

Respaldar la configuración, revisar colisiones de IDs y comprobar las reglas Docker base 87932, 87901 y 87903 del manager destino. El repositorio añade las reglas 100261–100264, 100270–100276 y, para stateful, 100280–100287. No sustituir el ruleset ni un `ossec.conf` completos.

Incorporar `manager/comun/lista.ejemplo.xml` dentro del ruleset existente. La CDB compara exactamente `poc.image_ref` y contiene `alpine:latest` y `docker.io/library/alpine:latest`. Es una excepción de política por referencia, no un certificado de ausencia de vulnerabilidades. Es distinta del filtro `allowed_repositories`, que limita qué puede analizar el wrapper.

Elegir solo uno de los fragmentos `integration.ejemplo.xml`: stateless o stateful. Incorporarlo dentro de `ossec_config`. El nombre del bloque coincide con el ejecutable en `integrations` y solo escucha la regla 100261.

Validar antes de reiniciar:

```sh
/var/ossec/bin/wazuh-analysisd -t
```

En el contenedor del lab se aplicó el cambio reiniciando el manager con su herramienta local de control (`wazuh-control restart`). Para un manager con systemd usar su servicio; no asumir que `systemctl` existe dentro del contenedor. La lista CDB se construye y carga al iniciar el motor. Conservar el respaldo para restaurar solo los cambios de este ensayo.

## Grype y caché

Obtener Grype 0.121.0 del repositorio oficial para Linux amd64, verificar los checksums oficiales y su versión. El artefacto usado fue `grype_0.121.0_linux_amd64.tar.gz`, con SHA256 `64e07133d3486115de647a66581461dccf5c732748a0a3119077395565f15519`. El repositorio no contiene ese binario.

La integración fija una caché explícita, desactiva la actualización automática durante el análisis y exige una base válida de como máximo 120 horas. Si la base caduca, los análisis dan error (reglas 100276 y 100286) hasta actualizarla. Preparar y actualizar la base de manera explícita antes de comparar dos análisis:

```sh
GRYPE_DB_CACHE_DIR=/var/ossec/queue/grype-poc/db /var/ossec/integrations/grype-poc-bin/grype --config /var/ossec/integrations/grype-poc.yaml db update
GRYPE_DB_CACHE_DIR=/var/ossec/queue/grype-poc/db /var/ossec/integrations/grype-poc-bin/grype --config /var/ossec/integrations/grype-poc.yaml db status
```

Ejecutar con permisos que dejen la caché accesible al usuario de Integrator. Registrar versión, fecha y schema antes de probar. Si se repite el lab otro día, pueden cambiar los hallazgos; los 14 de la prueba con alpine:3.19 no son una expectativa permanente.

El comando real de análisis que construye el core tiene esta forma:

```sh
grype registry:docker.io/library/alpine@sha256:DIGEST --scope squashed --platform linux/amd64 --config /var/ossec/integrations/grype-poc.yaml -o json
```

`DIGEST` es ilustrativo: el script usa el digest obtenido del evento enriquecido y verifica que el informe corresponde a la identidad y plataforma observadas. No analiza por `latest` a ciegas.

## Ensayo funcional

Con la configuración del agente y del manager aplicada y validada, y el wodle en marcha, ejecutar en una terminal de Windows:

```powershell
docker --context desktop-linux pull alpine:latest
docker --context desktop-linux pull alpine:3.19
docker --context desktop-linux pull alpine:3.19
```

Con la CDB incluida, `latest` no dispara Grype. `3.19` dispara dos análisis. Elegir una modalidad por ensayo y esperar a que termine cada análisis: un lock no bloqueante impide análisis concurrentes, pero no crea una cola de los rechazados. Usar una base de stateful nueva y vacía solo en un lab separado si se quiere ver el primer análisis; no borrar un estado existente para repetir la demo: usar un tag que no se haya visto.

Buscar las alertas en `/var/ossec/logs/alerts/alerts.json` y los errores operativos en los registros del manager. No depender de un número fijo de vulnerabilidades: comparar los dos resultados con la misma base y el mismo digest. El guion completo, con las consultas del dashboard, está en [demo.md](demo.md).

Para stateful, desde Linux y con las rutas instaladas:

```sh
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-grype-stateful --status
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-grype-stateful --flush
```

`--status` consulta el estado sin crearlo. `--flush` entrega los eventos pendientes al socket real; genera actividad y debe usarse en el ensayo previsto. El wrapper no inicia un servicio de reintentos: un nuevo disparo también intenta entregar pendientes. No inducir fallos sobre el socket ni sobre los procesos Wazuh; las [pruebas aisladas](pruebas-aisladas.md) cubren esos casos sin conectarse a Wazuh.

Para terminar, restaurar los cambios revisados del agente y del manager. Conservar el estado del ensayo si se quiere inspeccionar después; no confundir la SQLite persistida con un inventario actual.

## Dashboard

En Threat Hunting > Events, filtrar por `data.integration` (`grype_poc` o `grype_poc_stateful`), por `rule.id` y por agente. Los campos de cada hallazgo (imagen, digest, plataforma, CVE, paquete, severidad, cambio y resumen) cuelgan de `data.grype_poc.*`.

La PoC genera alertas JSON personalizadas. No se ha implementado una carga en el inventario nativo de Vulnerability Detection. La retención del índice y la eventual conservación de una alerta de apertura requieren una decisión aparte.

## Referencias oficiales

Las rutas y comportamientos del código proceden de los archivos originales y de los ensayos del lab. Para el mecanismo de integración y configuración se consultaron estas fuentes el 27/10/2026; volver a contrastarlas al cambiar de versión:

- [Integraciones personalizadas Wazuh](https://documentation.wazuh.com/current/user-manual/manager/integration-with-external-apis.html): nombre, directorio, permisos y alerta JSON.
- [CDB lists](https://documentation.wazuh.com/current/user-manual/ruleset/cdb-list.html): alta en ruleset y carga al reiniciar.
- [localfile](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/localfile.html): lectura de registros del agente.
- [wodle command](https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/wodle-command.html): opciones del wodle (consultado el 5/11/2026).
- [Notas Wazuh 4.14.8](https://documentation.wazuh.com/current/release-notes/release-4-14-8.html): referencia de la familia ensayada; el lab identificó el manager como rc2.
- [Docker events](https://docs.docker.com/reference/cli/docker/system/events/): stream, fechas y formato JSON.
- [Grype 0.121.0](https://github.com/anchore/grype/releases/tag/v0.121.0): release del binario usado.
- [Configuración Grype](https://oss.anchore.com/docs/reference/grype/configuration/) y [base de vulnerabilidades](https://oss.anchore.com/docs/guides/vulnerability/database/): caché y actualización.
