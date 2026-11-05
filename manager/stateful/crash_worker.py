"""Solo pruebas: termina este proceso de ensayo, nunca procesos Wazuh."""
import json
import os
import sys
from grype_state_store import StateStore

path,payload,stage = sys.argv[1:]
data = json.load(open(payload,encoding='utf-8'))
store = StateStore(path)
if stage == 'before':
    store.commit_scan(data['request'],data['findings'],data['metadata'],before_commit=lambda:os._exit(91))
else:
    store.commit_scan(data['request'],data['findings'],data['metadata'])
    os._exit(92)
