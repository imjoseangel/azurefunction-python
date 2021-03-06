# -*- coding: utf-8 -*-
# pylint: disable=W0123,W1203,W0703,R1710,W0612

from __future__ import (division, absolute_import, print_function,
                        unicode_literals)
from lib.util import parameters, account
from azure.mgmt.cosmosdb import CosmosDBManagementClient
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from azure.core.exceptions import ResourceNotFoundError, HttpResponseError

import azure.functions as func

import logging
from opencensus.ext.azure.log_exporter import AzureLogHandler

import os

logger = logging.getLogger(__name__)
logger.addHandler(AzureLogHandler(
    connection_string=os.environ['APPLICATIONINSIGHTS_CONNECTION_STRING']))


def main(req: func.HttpRequest) -> func.HttpResponse:

    logger.info('Python HTTP trigger function processed a request.')

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
        logger.exception("Subscription not found or not defined")
        return func.HttpResponse("Subscription not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    cosmosdb_key = parameters(req, 'cosmosdbkey')
    cosmosdb_values = ('primary', 'secondary')

    if cosmosdb_key not in cosmosdb_values:
        logger.error("CosmosDB key not found or not defined")
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
        logger.exception("KeyVault name not found or not defined")
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

                logger.info(
                    f"{cosmosdb_key.title()} Key for Database account "
                    f"{database_account} regenerated.")
                return func.HttpResponse(f"{cosmosdb_key.title()} Key for Database "
                                         f"account {database_account} regenerated.",
                                         status_code=200)

        except (ResourceNotFoundError, HttpResponseError):
            logger.exception(f"Database {database_account} not found.")
            return func.HttpResponse(f"Database {database_account} not found "
                                     f"in subscription {subscription_id}.",
                                     status_code=404)

        except Exception as e:
            logger.exception(f"{e}")
            return func.HttpResponse(f"{e}",
                                     status_code=500)
    else:
        logger.info(
            "CosmosDB and/or Resource Group Name not found or not defined")
        return func.HttpResponse(
            "CosmosDB and/or Resource Group Name not found or not defined \n\n"
            f"{syntax}",
            status_code=200
        )
