#!/usr/bin/env python3
import os
import tempfile
import sys

from core import db

print('Running lightweight test_notifications runner')
try:
    tmp = tempfile.TemporaryDirectory()
    os.environ['HARMATTAN_DATA'] = tmp.name
    # ensure DB initialized
    conn = db.get_conn()
    print('DB initialized at', conn)

    rule = db.add_alert_rule('t1', 'job.update', condition='')
    assert rule['name'] == 't1'
    print('add_alert_rule OK ->', rule)

    n = db.save_notification('job.update', {'job': {'id': 'abc', 'status': 'done'}})
    assert n['type'] == 'job.update'
    print('save_notification OK ->', n)

    nots = db.list_notifications(limit=10)
    if not any(x['type'] == 'job.update' for x in nots):
        raise AssertionError('saved notification not found in list_notifications')
    print('list_notifications OK ->', len(nots), 'notifications')

    print('ALL TESTS PASSED')
    sys.exit(0)
except Exception as e:
    print('TEST FAILED:', e)
    import traceback
    traceback.print_exc()
    sys.exit(2)
