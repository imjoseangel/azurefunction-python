import logging
import json

import azure.functions as func

from azure.core.exceptions import ResourceNotFoundError, HttpResponseError, ServiceRequestError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.cosmosdb import CosmosDBManagementClient


def _format(content):
    return json.dumps(content.serialize(keep_readonly=True), indent=4, separators=(',', ': '))


def main(req: func.HttpRequest) -> func.HttpResponse:

    logging.info('Python HTTP trigger function processed a request.')

    syntax = (f"Syntax:\n"
              f"-------\n"
              f"?subscriptionid=<subscriptionid>\n"
              f"&resourcegroup=<resourcegroup>\n"
              f"&cosmosdb=<cosmosdbname>\n"
              f"&cosmosdbkey=[ primary | secondary ]\n"
              f"&keyvaultname=<keyvaultname>\n")

    SUBSCRIPTION_ID = req.params.get('subscriptionid')

    if not SUBSCRIPTION_ID or SUBSCRIPTION_ID is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            SUBSCRIPTION_ID = req_body.get('subscriptionid')

    try:
        cosmosdb_client = CosmosDBManagementClient(
            credential=DefaultAzureCredential(),
            subscription_id=SUBSCRIPTION_ID
        )
    except ValueError:
        logging.error(f"Subscription not found or not defined")
        return func.HttpResponse(f"Subscription not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    COSMOSDBKEY = req.params.get('cosmosdbkey')
    COSMOSDBVALUES = ('primary', 'secondary')

    if not COSMOSDBKEY or COSMOSDBKEY is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            COSMOSDBKEY = req_body.get('cosmosdbkey')

    if COSMOSDBKEY not in COSMOSDBVALUES:
        logging.error(f"CosmosDB not found or not defined")
        return func.HttpResponse(f"CosmosDB not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    KEYVAULT_NAME = req.params.get('keyvaultname')

    if not KEYVAULT_NAME or KEYVAULT_NAME is None:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            KEYVAULT_NAME = req_body.get('keyvaultname')

    try:
        KVURI = f"https://{KEYVAULT_NAME}.vault.azure.net"

        keyvault_client = SecretClient(
            credential=DefaultAzureCredential(),
            vault_url=KVURI
        )

        keyvault_client.set_secret('dummy', 'dummy')

    except (NameError, ValueError, ServiceRequestError, ResourceNotFoundError):
        logging.error(f"KeyVault not found or not defined")
        return func.HttpResponse(f"KeyVault not found or not defined \n\n"
                                 f"{syntax}",
                                 status_code=404)

    DATABASE_ACCOUNT = req.params.get('cosmosdb')
    GROUP_NAME = req.params.get('resourcegroup')

    if not DATABASE_ACCOUNT or not GROUP_NAME:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            DATABASE_ACCOUNT = req_body.get('cosmosdb')
            GROUP_NAME = req_body.get('resourcegroup')

    if DATABASE_ACCOUNT and GROUP_NAME:
        try:
            regenerate_keys = cosmosdb_client.database_accounts.begin_regenerate_key(
                GROUP_NAME,
                DATABASE_ACCOUNT,
                cosmosdb_client.database_accounts.models.DatabaseAccountRegenerateKeyParameters(
                    key_kind=COSMOSDBKEY
                )
            )

            regenerate_keys.wait()

            if regenerate_keys.status() == "Succeeded":

                database_account_keys = cosmosdb_client.database_accounts.list_keys(
                    GROUP_NAME,
                    DATABASE_ACCOUNT
                )

                keyvault_client.set_secret(
                    f"{DATABASE_ACCOUNT}-{COSMOSDBKEY}",
                    eval(f"database_account_keys.{COSMOSDBKEY}_master_key")
                )

                logging.info(
                    f"{COSMOSDBKEY.title()} Key for Database account {DATABASE_ACCOUNT} regenerated.")
                return func.HttpResponse(f"{COSMOSDBKEY.title()} Key for Database account {DATABASE_ACCOUNT} regenerated.", status_code=200)

        except ResourceNotFoundError:
            logging.error(f"Database account {DATABASE_ACCOUNT} not found.")
            return func.HttpResponse(f"Database {DATABASE_ACCOUNT} not found.", status_code=404)

        except HttpResponseError:
            logging.error(f"Authorization Failed")
            return func.HttpResponse(f"Autorization Failed", status_code=500)

        except Exception as e:
            logging.error(f"{e}")
            return func.HttpResponse(f"{e}", status_code=500)
    else:
        logging.info(
            f"CosmosDB and/or Resource Group Name not found or not defined")
        return func.HttpResponse(
            f"CosmosDB and/or Resource Group Name not found or not defined \n\n"
            f"{syntax}",
            status_code=200
        )
