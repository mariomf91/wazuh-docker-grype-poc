"""Pruebas aisladas. No se conectan al socket de Wazuh ni escanean imágenes."""
import concurrent.futures
from contextlib import closing
import copy
import hashlib
import importlib.machinery
import importlib.util
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
import xml.etree.ElementTree as ET

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parent
from grype_state_store import StateStore, run_key

loader = importlib.machinery.SourceFileLoader('stateful_wrapper',str(ROOT/'custom-grype-stateful'))
spec = importlib.util.spec_from_loader(loader.name,loader)
wrapper = importlib.util.module_from_spec(spec)
loader.exec_module(wrapper)

REQUEST = {'agent':{'id':'003','name':'lab-win','ip':'192.0.2.20'},'engine_id':'TEST-ENGINE',
           'image_id':'sha256:'+'1'*64,'identity_kind':'manifest','image_ref':'alpine:3.19',
           'platform':'linux/amd64','target':'docker.io/library/alpine@sha256:'+'2'*64,
           'profile':'test-profile','trigger_id':'TEST-ONLY-1','event_ns':1793093980000000000}
FINDINGS = {'a'*64:{'finding_id':'a'*64,'vulnerability_id':'POC-SYNTHETIC-ONLY','namespace':'test:alpine',
                   'package':'test','version':'1','package_type':'apk','severity':'High','fix':'2'}}
METADATA = {'scanner_version':'0.121.0','scanner_image_id':'sha256:'+'8'*64,'db_built':'2026-10-27T06:30:41Z','db_schema':'v6.1.10'}
CONFIG = {'expected_grype_version':'0.121.0','max_flush_per_call':1000,'profile':'test-profile',
          'core_sha256':'a'*64,'profile_sha256':'b'*64}


class Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(dir=ROOT)
        self.addCleanup(self.tmp.cleanup)
        self.folder = Path(self.tmp.name)
        self.path = self.folder/'state.sqlite3'
        self.store = StateStore(self.path)
        self.request,self.findings,self.meta = copy.deepcopy(REQUEST),copy.deepcopy(FINDINGS),copy.deepcopy(METADATA)

    def rows(self):
        with closing(self.store.connect()) as db:
            return [dict(row) for row in db.execute('SELECT * FROM outbox ORDER BY seq')]

    def events(self):
        return [json.loads(row['payload_json'])['grype_poc'] for row in self.rows()]

    def test_first_commit_contains_snapshot_and_events(self):
        result = self.store.commit_scan(self.request,self.findings,self.meta)
        self.assertEqual(result['new_count'],1)
        status = StateStore.inspect(self.path)
        self.assertEqual((len(status['snapshots']),status['pending']),(1,2))

    def test_repeat_new_source_event_only_summary(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        next_request = dict(self.request,event_ns=self.request['event_ns']+1000,trigger_id='TEST-ONLY-2')
        result = self.store.commit_scan(next_request,self.findings,self.meta)
        self.assertEqual((result['new_count'],result['unchanged_count'],result['events_added']),(0,1,1))

    def test_replayed_old_event_does_not_regress_state(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        newer = dict(self.request,event_ns=self.request['event_ns']+1000)
        self.store.commit_scan(newer,self.findings,self.meta)
        result = self.store.commit_scan(self.request,{},self.meta)
        self.assertEqual(result['status'],'duplicate')
        self.assertEqual(StateStore.inspect(self.path)['snapshots'][0]['current_scan_findings'],1)

    def test_out_of_order_event_rejected(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        before = StateStore.inspect(self.path)
        with self.assertRaisesRegex(ValueError,'out_of_order'):
            self.store.commit_scan(dict(self.request,event_ns=self.request['event_ns']-1000),{},self.meta)
        self.assertEqual(StateStore.inspect(self.path),before)

    def test_new_digest_keeps_previous_image(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        result = self.store.commit_scan(dict(self.request,image_id='sha256:'+'3'*64),{},self.meta)
        self.assertEqual(result['not_observed_count'],0)
        self.assertEqual(sorted(r['current_scan_findings'] for r in StateStore.inspect(self.path)['snapshots']),[0,1])

    def test_agent_platform_profile_and_scanner_are_distinct(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        variants = [dict(self.request,agent={'id':'004','name':'other'}),dict(self.request,platform='linux/arm64'),
                    dict(self.request,profile='another-profile'),dict(self.request,identity_kind='config')]
        for request in variants:
            self.store.commit_scan(request,{},self.meta)
        self.store.commit_scan(self.request,{},dict(self.meta,scanner_version='0.122.0'))
        self.assertEqual(len(StateStore.inspect(self.path)['snapshots']),6)

    def test_database_downgrade_and_schema_change_rejected(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        newer = dict(self.request,event_ns=self.request['event_ns']+1000)
        for meta,reason in [(dict(self.meta,db_built='2026-10-26T00:00:00Z'),'database_downgrade'),
                            (dict(self.meta,db_schema='v7'),'database_schema_changed')]:
            with self.assertRaisesRegex(ValueError,reason):
                self.store.commit_scan(newer,{},meta)
        self.assertEqual(StateStore.inspect(self.path)['snapshots'][0]['current_scan_findings'],1)

    def test_absent_finding_is_not_a_confirmed_fix(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        result = self.store.commit_scan(dict(self.request,event_ns=self.request['event_ns']+1000),{},self.meta)
        self.assertEqual((result['not_observed_count'],result['closed_count']),(1,0))
        absent = [r for r in self.events() if r['event']=='not_observed']
        self.assertEqual(len(absent),1)
        self.assertIn('not_proof_of_fix',absent[0]['reason'])

    def test_changed_finding_emits_updated(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        self.findings['a'*64]['severity'] = 'Critical'
        result = self.store.commit_scan(dict(self.request,event_ns=self.request['event_ns']+1000),self.findings,self.meta)
        self.assertEqual((result['new_count'],result['updated_count']),(0,1))

    def test_failure_before_commit_rolls_back_both_tables(self):
        def fail():
            raise RuntimeError('synthetic_crash_before_commit')
        with self.assertRaises(RuntimeError):
            self.store.commit_scan(self.request,self.findings,self.meta,before_commit=fail)
        self.assertEqual(StateStore.inspect(self.path)['snapshots'],[])
        self.assertEqual(self.rows(),[])

    def crash(self,stage):
        path = self.folder/'crash.sqlite3'
        payload = self.folder/'payload.json'
        payload.write_text(json.dumps({'request':self.request,'findings':self.findings,'metadata':self.meta}),encoding='utf-8')
        result = subprocess.run([sys.executable,str(ROOT/'crash_worker.py'),str(path),str(payload),stage],capture_output=True)
        self.assertEqual(result.returncode,91 if stage=='before' else 92,result.stderr)
        return StateStore(path)

    def test_actual_process_exit_before_commit(self):
        store = self.crash('before')
        status = StateStore.inspect(store.path)
        self.assertEqual((status['snapshots'],status['pending']),([],0))

    def test_actual_process_exit_after_commit_keeps_pending(self):
        store = self.crash('after')
        status = StateStore.inspect(store.path)
        self.assertEqual((len(status['snapshots']),status['pending']),(1,2))
        sent = []
        self.assertEqual(store.drain(lambda event,agent:sent.append(event))['queued'],2)

    def test_send_failure_preserves_pending(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        def fail(event,agent):
            raise OSError('synthetic_unavailable_socket')
        delivery = self.store.drain(fail)
        self.assertEqual((delivery['queued'],delivery['pending']),(0,2))
        self.assertEqual(self.rows()[0]['attempts'],1)

    def test_retry_and_second_flush_are_idempotent(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        sent = []
        self.assertEqual(self.store.drain(lambda e,a:sent.append(e))['queued'],2)
        self.assertEqual(self.store.drain(lambda e,a:sent.append(e))['queued'],0)
        self.assertEqual(len(sent),2)
        self.assertTrue(self.store.has_run(run_key(self.request,self.meta['scanner_version'])))

    def test_partial_delivery_only_retries_pending(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        sent = []
        def sender(event,agent):
            if sent:
                raise OSError('synthetic_second_send_failure')
            sent.append(event)
        delivery = self.store.drain(sender)
        self.assertEqual((delivery['queued'],delivery['pending']),(1,1))
        self.assertEqual(self.store.drain(lambda e,a:sent.append(e))['queued'],1)
        self.assertEqual(len(sent),2)

    def test_ambiguous_send_can_duplicate_but_keeps_event_id(self):
        self.store.commit_scan(self.request,self.findings,self.meta)
        sent = []
        def after_send():
            raise RuntimeError('synthetic_crash_before_marking_queued')
        self.store.drain(lambda e,a:sent.append(e),after_send=after_send)
        self.store.drain(lambda e,a:sent.append(e))
        self.assertEqual(len(sent),3)
        self.assertEqual(sent[0]['grype_poc']['event_id'],sent[1]['grype_poc']['event_id'])

    def test_oversized_event_rolls_back_snapshot(self):
        self.findings['a'*64]['package'] = 'x'*6000
        with self.assertRaisesRegex(ValueError,'event_too_large'):
            self.store.commit_scan(self.request,self.findings,self.meta)
        self.assertEqual((StateStore.inspect(self.path)['snapshots'],self.rows()),([],[]))

    def test_pending_and_history_caps_fail_before_changing_state(self):
        for name,limits in [('pending',{'max_pending':1}),('history',{'max_rows':1})]:
            store = StateStore(self.folder/(name+'.sqlite3'),**limits)
            with self.assertRaisesRegex(ValueError,'outbox_'):
                store.commit_scan(self.request,self.findings,self.meta)
            self.assertEqual(StateStore.inspect(store.path)['snapshots'],[])

    def test_snapshot_cap_preserves_existing(self):
        store = StateStore(self.folder/'limited.sqlite3',max_scopes=1)
        store.commit_scan(self.request,self.findings,self.meta)
        with self.assertRaisesRegex(ValueError,'snapshot_limit'):
            store.commit_scan(dict(self.request,image_id='sha256:'+'3'*64),{},self.meta)
        self.assertEqual(len(StateStore.inspect(store.path)['snapshots']),1)

    def test_error_does_not_create_empty_snapshot_or_complete_run(self):
        self.store.record_error(self.request,self.meta,'synthetic_scan_error')
        self.assertEqual(StateStore.inspect(self.path)['snapshots'],[])
        self.assertFalse(self.store.has_run(run_key(self.request,self.meta['scanner_version'])))
        self.store.commit_scan(self.request,self.findings,self.meta)
        self.assertTrue(self.store.has_run(run_key(self.request,self.meta['scanner_version'])))

    def test_repeated_error_is_not_added_twice(self):
        self.assertTrue(self.store.record_error(self.request,self.meta,'synthetic_scan_error'))
        self.assertFalse(self.store.record_error(self.request,self.meta,'synthetic_scan_error'))
        self.assertEqual(len(self.rows()),1)

    def test_concurrent_writers_do_not_leave_old_snapshot(self):
        older = dict(self.request,event_ns=self.request['event_ns'])
        newer = dict(self.request,event_ns=self.request['event_ns']+1000)
        def commit(request):
            try:
                return self.store.commit_scan(request,self.findings,self.meta)['status']
            except ValueError as exc:
                return str(exc)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(commit,[older,newer]))
        self.assertEqual(StateStore.inspect(self.path)['snapshots'][0]['event_ns'],str(newer['event_ns']))
        self.assertTrue(all(r in ('committed','out_of_order_scan') for r in results))

    def test_readonly_status_does_not_create_database(self):
        path = self.folder/'missing.sqlite3'
        self.assertFalse(StateStore.inspect(path)['exists'])
        self.assertFalse(path.exists())

    def test_unrecognized_database_is_not_migrated(self):
        path = self.folder/'foreign.sqlite3'
        with closing(sqlite3.connect(path)) as db:
            db.execute('CREATE TABLE unrelated(value TEXT)')
            db.commit()
        with self.assertRaisesRegex(ValueError,'unrecognized_state_schema'):
            StateStore(path)

    def test_sqlite_connections_use_full_synchronization(self):
        with closing(self.store.connect()) as db:
            self.assertEqual(db.execute('PRAGMA synchronous').fetchone()[0],2)

    def test_enrich_rejects_missing_or_fractional_timestamp(self):
        for event in [{'Type':'image','Action':'pull'}, {'Type':'image','Action':'pull','timeNano':'123.5'}]:
            with self.assertRaises(ValueError):
                wrapper.enrich_request({'data':{'docker':event}},self.request,CONFIG)

    def test_enrich_rejects_wrong_event_envelope(self):
        with self.assertRaisesRegex(ValueError,'event_envelope_mismatch'):
            wrapper.enrich_request({'data':{'docker':{'Type':'container','Action':'create'}}},self.request,CONFIG)

    def test_process_error_keeps_snapshot(self):
        calls = []
        fake = SimpleNamespace(request_from_alert=lambda a,c:dict(self.request),queue_message=lambda e,a:b'ok',
                               run_grype=lambda r,c:(_ for _ in ()).throw(OSError('synthetic_scan_failure')))
        alert = {'data':{'docker':{'Type':'image','Action':'pull','timeNano':str(self.request['event_ns'])}}}
        request = wrapper.enrich_request(alert,self.request,CONFIG)
        self.store.commit_scan(dict(request,event_ns=request['event_ns']-1000),self.findings,self.meta)
        before = StateStore.inspect(self.path)['snapshots']
        result = wrapper.process_alert(alert,CONFIG,fake,self.store,lambda e,a:calls.append(e))
        self.assertEqual(result['status'],'error')
        self.assertEqual(StateStore.inspect(self.path)['snapshots'],before)

    def test_duplicate_process_does_not_scan_again(self):
        calls = []
        fake = SimpleNamespace(request_from_alert=lambda a,c:dict(self.request),queue_message=lambda e,a:b'ok',
                               run_grype=lambda r,c:calls.append('scan') or {},normalise_report=lambda d,r,c:(self.findings,self.meta))
        alert = {'data':{'docker':{'Type':'image','Action':'pull','timeNano':str(self.request['event_ns'])}}}
        send = lambda e,a:None
        first = wrapper.process_alert(alert,CONFIG,fake,self.store,send)
        second = wrapper.process_alert(alert,CONFIG,fake,self.store,send)
        self.assertEqual((first['status'],second['status'],len(calls)),('committed','duplicate',1))

    def test_fixture_cli_requires_explicit_sandbox(self):
        p = subprocess.run([sys.executable,str(ROOT/'custom-grype-stateful'),'unused','--report','unused','--stdout'],capture_output=True)
        self.assertEqual(p.returncode,2)
        self.assertIn(b'--sandbox-db',p.stderr)

    def test_fixture_cli_cannot_use_live_state_path(self):
        config = self.folder/'config.json'
        config.write_text(json.dumps({'state_db':str(self.path)}),encoding='utf-8')
        before = StateStore.inspect(self.path)
        p = subprocess.run([sys.executable,str(ROOT/'custom-grype-stateful'),'unused','--config',str(config),
                            '--report','unused','--stdout','--sandbox-db',str(self.path)],capture_output=True)
        self.assertEqual(p.returncode,2)
        self.assertEqual(StateStore.inspect(self.path),before)

    def test_cli_status_is_readonly_without_installed_core(self):
        config = self.folder/'config.json'
        path = self.folder/'must-not-exist.sqlite3'
        config.write_text(json.dumps({'state_db':str(path)}),encoding='utf-8')
        p = subprocess.run([sys.executable,str(ROOT/'custom-grype-stateful'),'--config',str(config),'--status'],capture_output=True,text=True)
        self.assertEqual(p.returncode,0,p.stderr)
        self.assertFalse(json.loads(p.stdout)['exists'])
        self.assertFalse(path.exists())

    def test_changed_core_rejected_before_import(self):
        core = self.folder/'core.py'
        core.write_text('raise RuntimeError("MUST_NOT_IMPORT")',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'core_script_changed'):
            wrapper.load_core({'core_path':str(core),'core_sha256':'0'*64})

    def test_changed_scan_profile_rejected_before_import(self):
        core,profile = self.folder/'core.py',self.folder/'profile.yaml'
        core.write_text('raise RuntimeError("MUST_NOT_IMPORT")',encoding='utf-8')
        profile.write_text('ignore: []',encoding='utf-8')
        with self.assertRaisesRegex(ValueError,'scan_profile_changed'):
            wrapper.load_core({'core_path':str(core),'core_sha256':hashlib.sha256(core.read_bytes()).hexdigest(),
                               'grype_config':str(profile),'profile_sha256':'0'*64})

    def test_duplicate_source_event_with_new_alert_id_does_not_scan(self):
        calls = []
        fake = SimpleNamespace(request_from_alert=lambda a,c:dict(self.request,trigger_id=a['id']),queue_message=lambda e,a:b'ok',
                               run_grype=lambda r,c:calls.append('scan') or {},normalise_report=lambda d,r,c:(self.findings,self.meta))
        event = {'Type':'image','Action':'pull','timeNano':str(self.request['event_ns'])}
        one = wrapper.process_alert({'id':'FIRST','data':{'docker':event}},CONFIG,fake,self.store,lambda e,a:None)
        two = wrapper.process_alert({'id':'REDELIVERED','data':{'docker':event}},CONFIG,fake,self.store,lambda e,a:None)
        self.assertEqual((one['status'],two['status'],len(calls)),('committed','duplicate',1))

    def test_failed_scan_can_retry_same_source_event(self):
        alert = {'data':{'docker':{'Type':'image','Action':'pull','timeNano':str(self.request['event_ns'])}}}
        request = wrapper.enrich_request(alert,self.request,CONFIG)
        self.store.commit_scan(dict(request,event_ns=request['event_ns']-1000),self.findings,self.meta)
        fake = SimpleNamespace(request_from_alert=lambda a,c:dict(self.request),queue_message=lambda e,a:b'ok',
                               run_grype=lambda r,c:(_ for _ in ()).throw(OSError('synthetic_scan_failure')),
                               normalise_report=lambda d,r,c:(self.findings,self.meta))
        first = wrapper.process_alert(alert,CONFIG,fake,self.store,lambda e,a:None)
        fake.run_grype = lambda r,c:{}
        second = wrapper.process_alert(alert,CONFIG,fake,self.store,lambda e,a:None)
        self.assertEqual((first['status'],second['status'],second['unchanged_count']),('error','committed',1))

    def test_rules_are_well_formed_and_unique(self):
        tree = ET.parse(ROOT/'poc_stateful_rules.xml')
        ids = [r.attrib['id'] for r in tree.findall('rule')]
        self.assertEqual(len(ids),len(set(ids)))


if __name__ == '__main__':
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(Tests)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    summary = {'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'python':sys.version,
               'sqlite':sqlite3.sqlite_version,'scope':'AISLADO: sin socket Wazuh ni escaneos Grype reales'}
    output = ROOT/('validation-windows.json' if sys.platform=='win32' else 'validation-linux.json')
    output.write_text(json.dumps(summary,indent=2),encoding='utf-8')
    sys.exit(0 if result.wasSuccessful() else 1)
