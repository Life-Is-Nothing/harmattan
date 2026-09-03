import os
import tempfile
import json

from core import db


def test_alert_rules_and_notifications(tmp_path):
    # ensure DB initialized in temp dir
    os.environ['HARMATTAN_DATA'] = str(tmp_path)
    db.get_conn()

    # add a rule
    rule = db.add_alert_rule('t1', 'job.update', condition='')
    assert rule['name'] == 't1'

    # save a notification
    n = db.save_notification('job.update', {'job': {'id': 'abc', 'status': 'done'}})
    assert n['type'] == 'job.update'

    nots = db.list_notifications(limit=10)
    assert any(x['type'] == 'job.update' for x in nots)
