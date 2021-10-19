# -*- coding: utf-8 -*-

from __future__ import (division, absolute_import, print_function,
                        unicode_literals)

import json


def parameters(req, param):

    object_id = req.params.get(param)

    if not object_id or object_id is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            object_id = req_body.get(param)

    return object_id


def account(req, param):

    account = req.params.get(param)
    group_name = req.params.get('resourcegroup')

    if not account or not group_name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            account = req_body.get(param)
            group_name = req_body.get('resourcegroup')

    return account, group_name


def format(content):
    return json.dumps(content.serialize(keep_readonly=True), indent=4,
                      separators=(',', ': '))
