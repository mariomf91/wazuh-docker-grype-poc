# Resultados del ensayo y límites

Resumen de las pruebas completadas, separadas de lo que solo está propuesto. Las validaciones originales en JSON no se incluyen en este repositorio: contenían identificadores del laboratorio. Los registros completos y la SQLite real tampoco.

## Comparación real (27 oct 2026)

| Caso con alpine:3.19 y misma base | Stateless | Stateful |
|---|---:|---:|
| Primer pull: avisos de hallazgos | 14 | 14 nuevos |
| Segundo pull: avisos de hallazgos | 14 repetidos | 0 nuevos; 14 sin cambios |
| Total entre ambos pulls | 28 | 14 |
| Grype se ejecuta en un pull nuevo | Sí | Sí |
| Resumen de análisis | Sí | Sí |

Se cuentan hallazgos de paquete/vulnerabilidad: los 14 correspondían a 6 identificadores distintos de vulnerabilidad, no a 14 CVE diferentes. La segunda imagen, alpine:3.20, tuvo 6 hallazgos y un snapshot independiente; no cerró los de 3.19. Hubo cero diferencias respecto a las referencias manuales comparadas por `finding_id`.

Base del ensayo: schema v6.1.10, construida el 27/10/2026 a las 06:30:41 UTC. Scanner: Grype 0.121.0. Un cambio de digest, de base o de perfil puede cambiar los resultados. No se actualizaron los datos durante la comparación.

## Recuperación y conservación de estado

- Un fallo controlado de envío dejó 7 eventos pendientes junto con el snapshot válido. Al recuperar la ruta, `--flush` entregó los 7; otro `--flush` entregó 0.
- Un fallo controlado del scanner conservó el snapshot anterior y produjo `scan_error`. No se comunicó un falso escaneo completo con cero vulnerabilidades.
- Reintentar la misma alerta fallida pudo completar el análisis. Reenviar una alerta ya completada devolvió `duplicate` sin volver a escanear.
- El cierre del ensayo relacionó 25 eventos del outbox con 25 `event_id` únicos en `alerts.json` del manager. No hubo pérdidas ni duplicados observados en ese ensayo.
- Pasaron 37 pruebas aisladas en Windows y en Linux (ver [pruebas-aisladas.md](pruebas-aisladas.md)). Incluyen caídas de procesos de prueba antes y después del commit y posibles duplicados tras el envío. No se mataron procesos Wazuh.

Los tiempos normales política→resumen de los dos ensayos stateful fueron 5,466 y 4,429 s; los de stateless, 4,080 y 2,734 s. No es un benchmark controlado ni permite atribuir la diferencia a SQLite.

## Colector como wodle (5 nov 2026)

Validado como LocalSystem en un agente Windows 11: se ejecuta cada 10 s, un `pull` llega a la alerta de política en unos 4 s y al resumen de Grype en unos 11 s (una medición). El detalle, con lo que no se probó, está en [wodle.md](wodle.md#pruebas-realizadas-5-nov-2026).

## Qué significa mantener estado

Stateful usa dos tablas: `snapshots` y `outbox`. Compara el último resultado válido del mismo agente, engine, digest o tipo de identidad, plataforma, perfil y versión del scanner. Genera `new`, `updated` o `not_observed` y un resumen de `unchanged`. Un digest distinto crea otro ámbito; no se modifica el snapshot de la imagen anterior.

SQLite guarda snapshot y eventos pendientes en una sola transacción `BEGIN IMMEDIATE` con `synchronous=FULL`. Si esa transacción falla, se revierte completa. Tras el commit, intenta enviar al socket de Wazuh. La transacción no incluye al manager ni al indexer.

Si el proceso cae después de enviar y antes de registrar `queued_at`, puede repetir el evento. El `event_id` permanece estable, pero no hay deduplicación automática en recepción ni garantía de entrega exactamente una vez. Un envío correcto al socket no es confirmación del indexer.

## Límites concretos

| Asunto | Estado de la PoC |
|---|---|
| Disparo | Pull fuera de la lista CDB; sin programación periódica |
| Windows | Colector como wodle validado como LocalSystem; sin rotación del JSONL ni supervisión |
| Podman / macOS | No validados |
| Identidad | Imagen inmutable por agente/engine; no estado por contenedor |
| `not_observed` | No implica resuelta ni exposición cerrada; `closed_count=0` |
| Tag que cambia de digest | Cuenta como ámbito nuevo; los hallazgos de la imagen anterior no se cierran |
| Imagen retirada / contenedor parado | Sin reconciliación de inventario |
| Reintentos de envío | En otra invocación o con `--flush`; sin servicio periódico |
| Análisis concurrentes | Lock no bloqueante; los rechazados no tienen cola de trabajo |
| Imágenes locales o privadas | Sin mecanismo de transferencia ni autenticación ensayado |
| Hallazgos | Snapshot de la última observación, no inventario vivo |
| Dashboard / índice | Alertas JSON propias, comprobadas en `alerts.json` y en el indexer |
| Vulnerability Detection nativo | Sin carga de estos resultados en su inventario |
| Escala / clúster | Sin prueba de carga ni estado compartido entre managers |
| Retención | Sin purga ni migraciones del estado, ni coordinación con la rotación de índices |
| Base de Grype | La integración exige una base de como máximo 120 h; pasado ese plazo los análisis dan error hasta actualizarla |

Límites configurados: 5.000 pendientes, 50.000 filas de outbox, 1.000 snapshots y 1.000 envíos por invocación; umbral de auditoría de 1 MiB; análisis con timeout de 180 s, informe máximo de 50 MiB y 10.000 hallazgos. Son topes de protección de laboratorio, no capacidad operativa validada.

## Decisiones abiertas

- Mantener un inventario actual o emitir cierres («resuelta»): ambos requieren ampliar el diseño.
- Seguir tag → digest para que un tag que cambia no abra un ámbito nuevo sin cerrar el anterior.
- Cola para los análisis que llegan a la vez.
- Alertas propias frente a carga en el inventario nativo de Vulnerability Detection.
- La rotación de índices puede separar un cambio posterior de su alerta original, y SQLite por sí sola no resuelve la presentación de ese historial.
- Tratamiento de los avisos `recovered` y `gap` del colector (regla 100264).

Este repositorio no instala ni activa nada por sí mismo.
