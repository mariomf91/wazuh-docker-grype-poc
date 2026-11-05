# Guion de demostración

Muestra el flujo completo con pulls de imágenes en un equipo Windows: primero con la integración stateless y después con la stateful. Dura unos 15 minutos.

**Requisitos:** manager y agente configurados ([guia-lab.md](guia-lab.md), [wodle.md](wodle.md)), Docker Desktop abierto, wodle en marcha y base de Grype vigente (máximo 120 h).

**Conviene tener abiertas:** una terminal de Windows para `docker`, una consola del manager como root y el dashboard (Threat Hunting > Events) filtrado por el agente. En el dashboard, las columnas de Grype se añaden desde «available fields» buscando `grype_poc`.

En los ejemplos, `<agente>` es el nombre del agente Windows y `<manager>` el contenedor o equipo del manager.

## 1. Imagen permitida: solo se registra el evento

Dashboard: `agent.name:"<agente>" AND (rule.id:87932 OR rule.id:100261)`

```powershell
docker --context desktop-linux pull alpine:latest
```

**Se ve:** una sola fila, la regla 87932 (evento Docker, nivel 3). `alpine:latest` está en la lista CDB, así que no salta la regla 100261 ni se lanza Grype.

## 2. Imagen no permitida, sin memoria (stateless)

Con la integración stateless activa. Dashboard: `rule.id:100261 OR data.integration:"grype_poc"`

```powershell
docker --context desktop-linux pull alpine:3.21
```

**Se ve** (unos 10 s, con *Refresh*): la regla 100261 (nivel 10, imagen fuera de la lista), un aviso por hallazgo y el resumen 100275. Con la base de Grype del 4 nov 2026, `alpine:3.21` dio 3 hallazgos Medium (100273) y el resumen «3 hallazgos». El número depende de la fecha de la base.

## 3. Repetir el pull

Repetir el mismo `pull alpine:3.21`. **Se ve** otra vez la regla 100261 y **todos** los hallazgos de nuevo: sin memoria, el sistema no sabe que ya los avisó.

## 4. Cambiar a stateful

En el manager, como root. Se sustituye el nombre de la integración, se valida y se reinicia (6-12 s):

```sh
sed -i 's#<name>custom-grype</name>#<name>custom-grype-stateful</name>#' /var/ossec/etc/ossec.conf
/var/ossec/bin/wazuh-analysisd -t
/var/ossec/bin/wazuh-control restart
grep 'Enabling integration' /var/ossec/logs/ossec.log | tail -1
```

**Se ve:** `Enabling integration for: 'custom-grype-stateful'`. Solo hay una integración activa a la vez. Para volver a stateless, el `sed` inverso y los mismos tres comandos.

Comprobar que el agente sigue conectado antes del siguiente pull:

```sh
/var/ossec/bin/agent_control -l | grep <agente>
```

## 5. Con memoria: solo lo nuevo

Usar un tag que el manager **no haya visto nunca**. La memoria se identifica por el digest de la imagen y no se borra para repetir la demo: si se reutiliza un tag, el segundo ensayo ya no verá nada nuevo.

Dashboard: `agent.name:"<agente>" AND data.integration:"grype_poc_stateful"`

```powershell
docker --context desktop-linux pull alpine:3.18
```

**Se ve** (primer pull): una fila por hallazgo, todas «Grype stateful **new**», y el resumen 100285 con «N hallazgos; N nuevos, 0 sin cambios». Con la base del 4 nov 2026, `alpine:3.18` dio 14 hallazgos: 2 High (100282), 6 Medium (100283) y 6 Low (100284); Grype avisa de que 3.18 está fuera de soporte y sus datos pueden estar incompletos.

Repetir el mismo `pull`. **Se ve** una sola fila nueva, el resumen: «N hallazgos; **0 nuevos, N sin cambios**». Los hallazgos no se repiten.

## 6. Enseñar la memoria

```sh
/var/ossec/framework/python/bin/python3 /var/ossec/integrations/custom-grype-stateful --status
```

**Se ve:** un JSON con una entrada por imagen (`image_ref`, `current_scan_findings`, `observed_at` en UTC) y, al final, `"pending": 0`.

- Una foto por imagen, atada a su digest exacto; sobrevive a reinicios.
- `outbox_rows` son los avisos registrados; `pending: 0`, que no queda ninguno esperando.
- `delivery_ack`: la entrega se confirma hasta el socket local, **no hasta el indexer**.

## Reglas de resultado

| Modo | Reglas | Qué son |
|---|---|---|
| Política | 100261 / 100262 / 100263 (nivel 10) | `pull` de imagen / `create` / `start` de contenedor fuera de la lista CDB |
| Colector | 100264 (nivel 7) | Aviso del propio colector (ver [límites](wodle.md#límites-conocidos)) |
| Stateless | 100271 Critical (14), 100272 High (12), 100273 Medium (7), 100274 Low/Negligible/Unknown (3) | Un hallazgo |
| Stateless | 100275 (3) / 100276 (7) | Resumen del análisis / error del análisis |
| Stateful | 100281 Critical (14), 100282 High (12), 100283 Medium (7), 100284 Low/Negligible/Unknown (3) | Un hallazgo, con su cambio (`new`, `updated`) |
| Stateful | 100285 (3) / 100286 (7) | Resumen con nuevos y sin cambios / error (no sustituye el estado por uno vacío) |
| Stateful | 100287 (3) | Hallazgo «ya no observado»; no implica corrección confirmada |

## Puntos que conviene contar

- **No hay alerta de «resuelta».** Si un hallazgo deja de salir, el aviso 100287 dice «ya no observado».
- **La memoria se identifica por el digest, no por el tag.** Si `latest` pasa a otra imagen, cuenta como nueva y los hallazgos de la anterior no se cierran. Propuesta: seguir tag → digest.
- **Un análisis cada vez.** Los pulls concurrentes se rechazan: no hay cola.
- **Son alertas propias de la PoC,** no el inventario nativo de Vulnerability Detection.
- **La entrega confirma solo hasta el socket local.** Además, la memoria (SQLite, que no se borra) y los índices (que rotan) tienen vidas distintas.

## Si algo no sale

- **Sin filas tras el pull:** esperar 10-15 s y pulsar *Refresh*. El wodle lee cada 10 s y el análisis tarda unos segundos más.
- **Error de análisis (reglas 100276 / 100286):** la base de Grype puede haber caducado (más de 120 h). Actualizarla según [guia-lab.md](guia-lab.md#grype-y-caché).
- **El agente no aparece activo:** tras reiniciar el manager puede tardar unos segundos; comprobarlo con `agent_control -l`.
- **Docker Desktop no arranca** con un error de WSL del tipo `no sd* disk`: en un PowerShell como administrador, `Restart-Service WslService -Force`, cerrar Docker Desktop del todo y abrirlo de nuevo. No usar «Reset to factory defaults» ni «Purge data»: borran los datos de Docker.
