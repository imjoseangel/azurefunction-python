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
from azure.mgmt.cosmosdb import CosmosDBManagementClient


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


def main(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('Python HTTP trigger function processed a request.')

    syntax = ("Syntax:\n"
              "-------\n\n"
              "?cosmosdb=<cosmosdbname>\n"
              "&resourcegroup=<resourcegroup>\n"
              "&subscriptionid=<subscriptionid>\n"
              "&cosmosdbkey=[ primary | secondary ]\n"
              "&keyvaultname=<keyvaultname>\n\n"
              "OR with BODY POST:\n\n"
              '{\n'
              '"cosmosdb": "<cosmosdbname>",\n'
              '"resourcegroup": "<resourcegroup>",\n'
              '"subscriptionid": "<subscriptionid>",\n'
              '"cosmosdbkey": "<primary | secondary>",\n'
              '"keyvaultname": "<keyvaultname>"\n'
              '}')

    subscription_id = parameters(req, 'subscriptionid')

    try:
        cosmosdb_client = CosmosDBManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=subscription_id
        )
    except ValueError:
        logging.error("Subscription not found or not defined")
        return func.HttpResponse("Subscription not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    cosmosdb_key = parameters(req, 'cosmosdbkey')
    cosmosdb_values = ('primary', 'secondary')

    if cosmosdb_key not in cosmosdb_values:
        logging.error("CosmosDB key not found or not defined")
        return func.HttpResponse("CosmosDB key not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    keyvault_name = parameters(req, param='keyvaultname')

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

    database_account, group_name = account(req, param='cosmosdb')

    if database_account and group_name:
        try:
            regenerate_keys = cosmosdb_client.database_accounts.begin_regenerate_key(
                group_name,
                database_account,
                cosmosdb_client.database_accounts.models.DatabaseAccountRegenerateKeyParameters(
                    key_kind=cosmosdb_key
                )
            )

            regenerate_keys.wait()

            if regenerate_keys.status() == "Succeeded":

                database_account_keys = cosmosdb_client.database_accounts.list_keys(
                    group_name,
                    database_account
                )

                keyvault_client.set_secret(
                    f"{database_account}-{cosmosdb_key}",
                    eval(
                        f"database_account_keys.{cosmosdb_key}_master_key")
                )

                logging.info(
                    f"{cosmosdb_key.title()} Key for Database account "
                    f"{database_account} regenerated.")
                return func.HttpResponse(f"{cosmosdb_key.title()} Key for Database "
                                         f"account {database_account} regenerated.",
                                         status_code=200)

        except (ResourceNotFoundError, HttpResponseError):
            logging.error(f"Database {database_account} not found.")
            return func.HttpResponse(f"Database {database_account} not found "
                                     f"in subscription {subscription_id}.",
                                     status_code=404)

        except Exception as e:
            logging.error(f"{e}")
            return func.HttpResponse(f"{e}",
                                     status_code=500)
    else:
        logging.info(
            "CosmosDB and/or Resource Group Name not found or not defined")
        return func.HttpResponse(
            "CosmosDB and/or Resource Group Name not found or not defined \n\n"
            f"{syntax}",
            status_code=200
        )
