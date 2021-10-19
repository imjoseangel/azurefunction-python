import logging
import json

import azure.functions as func

from azure.core.exceptions import ResourceNotFoundError, HttpResponseError
from azure.core.exceptions import ServiceRequestError
from azure.core.exceptions import ClientAuthenticationError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient


def _format(content):
    return json.dumps(content.serialize(keep_readonly=True), indent=4,
                      separators=(',', ': '))


def main(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('Python HTTP trigger function processed a request.')

    syntax = (f"Syntax:\n"
              f"-------\n\n"
              f"?cosmosdb=<cosmosdbname>\n"
              f"&resourcegroup=<resourcegroup>\n"
              f"&subscriptionid=<subscriptionid>\n"
              f"&cosmosdbkey=[ primary | secondary ]\n"
              f"&keyvaultname=<keyvaultname>\n\n"
              f"OR with BODY POST:\n\n"
              f'{{\n'
              f'"cosmosdb": "<cosmosdbname>",\n'
              f'"resourcegroup": "<resourcegroup>",\n'
              f'"subscriptionid": "<subscriptionid>",\n'
              f'"cosmosdbkey": "<primary | secondary>",\n'
              f'"keyvaultname": "<keyvaultname>"\n'
              f'}}')

    subscription_id = req.params.get('subscriptionid')

    if not subscription_id or subscription_id is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            subscription_id = req_body.get('subscriptionid')

    try:
        cosmosdb_client = CosmosDBManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=subscription_id
        )
    except ValueError:
        logging.error(f"Subscription not found or not defined")
        return func.HttpResponse(f"Subscription not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    cosmosdb_key = req.params.get('cosmosdbkey')
    cosmosdb_values = ('primary', 'secondary')

    if not cosmosdb_key or cosmosdb_key is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            cosmosdb_key = req_body.get('cosmosdbkey')

    if cosmosdb_key not in cosmosdb_values:
        logging.error(f"CosmosDB key not found or not defined")
        return func.HttpResponse(f"CosmosDB key not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    keyvault_name = req.params.get('keyvaultname')

    if not keyvault_name or keyvault_name is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            keyvault_name = req_body.get('keyvaultname')

    try:
        kv_uri = f"https://{keyvault_name}.vault.azure.net"

        keyvault_client = SecretClient(
            credential=DefaultAzureCredential(),
            vault_url=kv_uri
        )

        keyvault_client.set_secret('dummy', 'dummy')

    except (NameError, ValueError, ServiceRequestError, ResourceNotFoundError,
            ClientAuthenticationError):
        logging.error(f"KeyVault name not found or not defined")
        return func.HttpResponse(f"KeyVault name not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    database_account = req.params.get('cosmosdb')
    group_name = req.params.get('resourcegroup')

    if not database_account or not group_name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            database_account = req_body.get('cosmosdb')
            group_name = req_body.get('resourcegroup')

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
                    eval(f"database_account_keys.{cosmosdb_key}_master_key")
                )

                logging.info(
                    f"{cosmosdb_key.title()} Key for Database account "
                    f"{database_account} regenerated.")
                return func.HttpResponse(f"{cosmosdb_key.title()} Key for Database "
                                         f"account {database_account} regenerated.",
                                         status_code=200)

        except ResourceNotFoundError:
            logging.error(f"Database account {database_account} not found.")
            return func.HttpResponse(f"Database {database_account} not found.",
                                     status_code=404)

        except HttpResponseError:
            logging.error(f"Authorization Failed")
            return func.HttpResponse(f"Autorization Failed",
                                     status_code=500)

        except Exception as e:
            logging.error(f"{e}")
            return func.HttpResponse(f"{e}",
                                     status_code=500)
    else:
        logging.info(
            f"CosmosDB and/or Resource Group Name not found or not defined")
        return func.HttpResponse(
            f"CosmosDB and/or Resource Group Name not found or not defined \n\n"
            f"{syntax}",
            status_code=200
        )
