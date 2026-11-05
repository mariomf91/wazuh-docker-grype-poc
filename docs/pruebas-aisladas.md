# Pruebas aisladas

`manager/stateful/test_stateful.py` usa `unittest` y la biblioteca estándar de Python. No necesita Grype, Docker ni conexión a Wazuh. Tiene 37 casos y crea datos sintéticos en directorios temporales de su propia carpeta; al terminar escribe `validation-windows.json` o `validation-linux.json` junto al script (el `.gitignore` los excluye).

Ejecutar desde `manager/stateful`, con todos los archivos de esa carpeta juntos:

```powershell
py -3.12 -B .\test_stateful.py
```

En Linux, con Python 3.10 o superior:

```sh
python3 -B test_stateful.py
```

`crash_worker.py` termina únicamente su propio proceso de ensayo para comprobar el comportamiento antes y después del commit. No es un servicio ni un comando para ejecutar contra el manager real.

Los tests usan identidades y hallazgos sintéticos marcados como `TEST`/`POC-SYNTHETIC-ONLY`. No se conectan al socket del manager ni publican hallazgos. Cubren estado inicial, repetido y modificado, aislamiento de identidades, rollback, caída después del commit, orden de eventos, antigüedad y schema de la base, límites, fallos de envío, entrega parcial y duplicado posible después de enviar.

Resultado del ensayo original (27 oct 2026): 37 pruebas correctas en Windows (Python 3.12.12, SQLite 3.51.1) y en Linux del manager (Python 3.10.20, SQLite 3.50.4).

El colector de Windows no tiene pruebas automáticas; sus pruebas manuales están en [wodle.md](wodle.md#pruebas-realizadas-5-nov-2026).
