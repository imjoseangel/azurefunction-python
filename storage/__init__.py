# -*- coding: utf-8 -*-
# pylint: disable=W0123,W1203,W0703,R1710,W0612

from __future__ import (division, absolute_import, print_function,
                        unicode_literals)

import logging
import json

import azure.functions as func

from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.storage import StorageManagementClient


def _format(content):
    return json.dumps(content.serialize(keep_readonly=True), indent=4,
                      separators=(',', ': '))


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


def storage(req):

    storage_account = req.params.get('storage')
    group_name = req.params.get('resourcegroup')

    if not storage_account or not group_name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            storage_account = req_body.get('storage')
            group_name = req_body.get('resourcegroup')

    return storage_account, group_name


def main(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('Python HTTP trigger function processed a request.')

    syntax = ("Syntax:\n"
              "-------\n\n"
              "?storage=<storagename>\n"
              "&resourcegroup=<resourcegroup>\n"
              "&subscriptionid=<subscriptionid>\n"
              "&storagekey=[ key1 | key2 ]\n"
              "&keyvaultname=<keyvaultname>\n\n"
              "OR with BODY POST:\n\n"
              '{\n'
              '"storage": "<storagename>",\n'
              '"resourcegroup": "<resourcegroup>",\n'
              '"subscriptionid": "<subscriptionid>",\n'
              '"storagekey": "<key1 | key2>",\n'
              '"keyvaultname": "<keyvaultname>"\n'
              '}')

    subscription_id = parameters(req, 'subscriptionid')

    try:
        storage_client = StorageManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=subscription_id
        )
    except ValueError:
        logging.error("Subscription not found or not defined")
        return func.HttpResponse("Subscription not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    storage_key = parameters(req, 'storagekey')
    storage_values = ('key1', 'key2')

    if storage_key not in storage_values:
        logging.error("Storage Account key not found or not defined")
        return func.HttpResponse("Storage Account key not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    keyvault_name = parameters(req, 'keyvaultname')

    try:
        kv_uri = f"https://{keyvault_name}.vault.azure.net"

        keyvault_client = SecretClient(
            credential=DefaultAzureCredential(),
            vault_url=kv_uri
        )

        keyvault_client.set_secret('dummy', 'dummy')

    except Exception:
        logging.error("KeyVault name not found or not defined")
        return func.HttpResponse("KeyVault name not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    storage_account, group_name = storage(req)

    if storage_account and group_name:
        try:
            storage_client.storage_accounts.regenerate_key(
                group_name,
                storage_account,
                storage_key
            )

            storage_account_keys = storage_client.storage_accounts.list_keys(
                group_name,
                storage_account
            )

            storage_keys = {
                key.key_name: key.value for key in storage_account_keys.keys}

            keyvault_client.set_secret(
                f"{storage_account}-{storage_key}",
                eval(f"storage_keys[{storage_key}]")
            )

            logging.info(
                f"{storage_key.title()} Key for Storage account "
                f"{storage_account} regenerated.")
            return func.HttpResponse(f"{storage_key.title()} Key for Storage "
                                     f"account {storage_account} regenerated.",
                                     status_code=200)

        except (ResourceNotFoundError, HttpResponseError):
            logging.error(f"Storage {storage_account} not found.")
            return func.HttpResponse(f"Storage {storage_account} not found "
                                     f"in subscription {subscription_id}.",
                                     status_code=404)

        except Exception as e:
            logging.error(f"{e}")
            return func.HttpResponse(f"{e}",
                                     status_code=500)
    else:
        logging.info(
            "Storage Account and/or Resource Group Name not found or not defined")
        return func.HttpResponse(
            "Storage Account and/or Resource Group Name not found or not defined \n\n"
            f"{syntax}",
            status_code=200
        )
