"""Borrador PoC: snapshots + outbox en una sola transacción SQLite.

El llamador serializa scan/commit/flush mediante un lock de proceso.
queued_at confirma únicamente que send() al socket local terminó: no es un ACK del indexer.
"""
from contextlib import closing, contextmanager
import datetime as dt
import hashlib
import json
from pathlib import Path
import sqlite3

SCHEMA_VERSION = 1


def utc_now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def digest(value):
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def scope_key(request, scanner_version):
    return digest([request['agent']['id'], request['engine_id'], request['identity_kind'],
                   request['image_id'], request['platform'], request['profile'], scanner_version])


def run_key(request, scanner_version):
    return digest([scope_key(request, scanner_version), request['event_ns'], 'image', 'pull'])


@contextmanager
def transaction(db):
    db.execute('BEGIN IMMEDIATE')
    try:
        yield
        db.execute('COMMIT')
    except BaseException:
        if db.in_transaction:
            db.execute('ROLLBACK')
        raise


class StateStore:
    def __init__(self, path, max_pending=5000, max_rows=50000, max_scopes=1000):
        self.path = Path(path)
        self.max_pending, self.max_rows, self.max_scopes = max_pending, max_rows, max_scopes
        if not self.path.parent.is_dir():
            raise ValueError('state_directory_missing')
        with closing(self.connect()) as db, transaction(db):
            version = db.execute('PRAGMA user_version').fetchone()[0]
            tables = [r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
            if version not in (0, SCHEMA_VERSION) or (version == 0 and tables):
                raise ValueError('unrecognized_state_schema')
            db.execute('''CREATE TABLE IF NOT EXISTS snapshots (
              scope_key TEXT PRIMARY KEY, identity_json TEXT NOT NULL, findings_json TEXT NOT NULL,
              db_built TEXT NOT NULL, db_schema TEXT NOT NULL, event_ns INTEGER NOT NULL,
              observed_at TEXT NOT NULL, run_id TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS outbox (
              seq INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
              run_id TEXT NOT NULL, scope_key TEXT NOT NULL, agent_json TEXT NOT NULL,
              payload_json TEXT NOT NULL, queued_at TEXT, attempts INTEGER NOT NULL DEFAULT 0,
              last_error TEXT)''')
            db.execute('CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(queued_at,seq)')
            db.execute('PRAGMA user_version=1')

    def connect(self):
        db = sqlite3.connect(str(self.path), timeout=5, isolation_level=None)
        db.row_factory = sqlite3.Row
        db.execute('PRAGMA synchronous=FULL')
        return db

    def has_run(self, run_id):
        with closing(self.connect()) as db:
            return db.execute('SELECT 1 FROM outbox WHERE event_id=?', (digest([run_id,'scan_complete']),)).fetchone() is not None

    def _check_limits(self, db, extra_events, new_scope=False):
        total, pending = db.execute('SELECT COUNT(*),COALESCE(SUM(queued_at IS NULL),0) FROM outbox').fetchone()
        if total + extra_events > self.max_rows:
            raise ValueError('outbox_history_limit_review_required')
        if pending + extra_events > self.max_pending:
            raise ValueError('outbox_pending_limit')
        if new_scope and db.execute('SELECT COUNT(*) FROM snapshots').fetchone()[0] >= self.max_scopes:
            raise ValueError('snapshot_limit')

    @staticmethod
    def base(request, metadata, run_id):
        keys = ('image_id','identity_kind','image_ref','platform','target','engine_id','profile','trigger_id')
        result = {key: request[key] for key in keys}
        result.update(metadata)
        result.update(mode='stateful',run_id=run_id,source_event_ns=str(request['event_ns']))
        return result

    def _event(self, db, request, metadata, run_id, scope, semantic_id, fields, validate_event):
        event_id = digest([run_id,semantic_id])
        body = dict(self.base(request,metadata,run_id), event_id=event_id, **fields)
        event = {'integration':'grype_poc_stateful','grype_poc':body}
        if len(canonical(event).encode()) > 5000:
            raise ValueError('event_too_large')
        if validate_event is not None:
            validate_event(event)
        db.execute('INSERT INTO outbox(event_id,run_id,scope_key,agent_json,payload_json) VALUES(?,?,?,?,?)',
                   (event_id,run_id,scope,canonical(request['agent']),canonical(event)))

    def commit_scan(self, request, findings, metadata, validate_event=None, before_commit=None):
        scope = scope_key(request,metadata['scanner_version'])
        run_id = run_key(request,metadata['scanner_version'])
        with closing(self.connect()) as db, transaction(db):
            if db.execute('SELECT 1 FROM outbox WHERE event_id=?',(digest([run_id,'scan_complete']),)).fetchone():
                return {'status':'duplicate','run_id':run_id,'events_added':0}
            row = db.execute('SELECT * FROM snapshots WHERE scope_key=?',(scope,)).fetchone()
            previous = json.loads(row['findings_json']) if row else {}
            if row:
                if request['event_ns'] <= row['event_ns']:
                    raise ValueError('out_of_order_scan')
                if dt.datetime.fromisoformat(metadata['db_built'].replace('Z','+00:00')) < dt.datetime.fromisoformat(row['db_built'].replace('Z','+00:00')):
                    raise ValueError('database_downgrade')
                if metadata['db_schema'] != row['db_schema']:
                    raise ValueError('database_schema_changed_review_required')
            new = sorted(set(findings)-set(previous))
            absent = sorted(set(previous)-set(findings))
            updated = sorted(k for k in set(previous)&set(findings) if previous[k] != findings[k])
            unchanged = len(set(previous)&set(findings))-len(updated)
            count = len(new)+len(absent)+len(updated)+1
            self._check_limits(db,count,new_scope=row is None)
            for change,keys,source in [('new',new,findings),('updated',updated,findings),('not_observed',absent,previous)]:
                for key in keys:
                    fields = dict(source[key],event='not_observed' if change=='not_observed' else 'finding',change=change)
                    if change == 'not_observed':
                        fields['reason'] = 'absent_in_successful_comparable_scan_not_proof_of_fix'
                    self._event(db,request,metadata,run_id,scope,change+':'+key,fields,validate_event)
            summary = {'event':'scan_complete','total':len(findings),'new_count':len(new),'updated_count':len(updated),
                       'not_observed_count':len(absent),'unchanged_count':unchanged,'closed_count':0}
            self._event(db,request,metadata,run_id,scope,'scan_complete',summary,validate_event)
            identity = {k:request[k] for k in ('image_id','identity_kind','image_ref','platform','target','engine_id','profile')}
            identity['agent_id'] = request['agent']['id']
            db.execute('''INSERT INTO snapshots VALUES(?,?,?,?,?,?,?,?) ON CONFLICT(scope_key) DO UPDATE SET
              identity_json=excluded.identity_json,findings_json=excluded.findings_json,db_built=excluded.db_built,
              db_schema=excluded.db_schema,event_ns=excluded.event_ns,observed_at=excluded.observed_at,run_id=excluded.run_id''',
              (scope,canonical(identity),canonical(findings),metadata['db_built'],metadata['db_schema'],request['event_ns'],utc_now(),run_id))
            if before_commit is not None:
                before_commit()
            return dict(summary,status='committed',run_id=run_id,scope_key=scope,events_added=count)

    def record_error(self, request, metadata, reason, validate_event=None):
        scope = scope_key(request,metadata['scanner_version'])
        run_id = run_key(request,metadata['scanner_version'])
        event_id = digest([run_id,'error:'+reason])
        with closing(self.connect()) as db, transaction(db):
            if db.execute('SELECT 1 FROM outbox WHERE event_id=?',(event_id,)).fetchone():
                return False
            self._check_limits(db,1)
            self._event(db,request,metadata,run_id,scope,'error:'+reason,{'event':'scan_error','reason':reason},validate_event)
        return True

    def drain(self, send, limit=1000, after_send=None):
        """Debe llamarse bajo el lock exterior. No mantiene una transacción durante send()."""
        sent = 0
        with closing(self.connect()) as db:
            for _ in range(limit):
                row = db.execute('SELECT * FROM outbox WHERE queued_at IS NULL ORDER BY seq LIMIT 1').fetchone()
                if row is None:
                    break
                try:
                    event,agent = json.loads(row['payload_json']),json.loads(row['agent_json'])
                    send(event,agent)
                    if after_send is not None:
                        after_send()
                except Exception as exc:
                    db.execute('UPDATE outbox SET attempts=attempts+1,last_error=? WHERE seq=?', (type(exc).__name__,row['seq']))
                    return {'queued':sent,'pending':db.execute('SELECT COUNT(*) FROM outbox WHERE queued_at IS NULL').fetchone()[0],
                            'error':type(exc).__name__}
                db.execute('UPDATE outbox SET queued_at=?,attempts=attempts+1,last_error=NULL WHERE seq=?',(utc_now(),row['seq']))
                sent += 1
            return {'queued':sent,'pending':db.execute('SELECT COUNT(*) FROM outbox WHERE queued_at IS NULL').fetchone()[0]}

    @staticmethod
    def inspect(path):
        path = Path(path)
        if not path.exists():
            return {'exists':False,'snapshots':[],'outbox_rows':0,'pending':0}
        with closing(sqlite3.connect(path.resolve().as_uri()+'?mode=ro',uri=True)) as db:
            db.row_factory = sqlite3.Row
            if db.execute('PRAGMA user_version').fetchone()[0] != SCHEMA_VERSION:
                raise ValueError('unrecognized_state_schema')
            snapshots = []
            for row in db.execute('SELECT * FROM snapshots ORDER BY observed_at'):
                value = json.loads(row['identity_json'])
                value.update(scope_key=row['scope_key'],current_scan_findings=len(json.loads(row['findings_json'])),
                             observed_at=row['observed_at'],db_built=row['db_built'],event_ns=str(row['event_ns']),presence='last_observed_only')
                snapshots.append(value)
            total,pending = db.execute('SELECT COUNT(*),COALESCE(SUM(queued_at IS NULL),0) FROM outbox').fetchone()
            return {'exists':True,'schema':SCHEMA_VERSION,'snapshots':snapshots,'outbox_rows':total,'pending':pending,
                    'delivery_ack':'local_socket_send_only_not_indexer_ack'}
