# Python Keys Rotate Function
Azure Function to rotate CosmosDB and Storage Account Keys

Both functions can be used whether with params using GET or with a JSON Body using POST

With Params:

```
?cosmosdb=<cosmosdbname>
&resourcegroup=<resourcegroup>
&subscriptionid=<subscriptionid>
&cosmosdbkey=[ primary | secondary ]
&keyvaultname=<keyvaultname>
```

With POST

```json
{
"cosmosdb": "<cosmosdbname>",
"resourcegroup": "<resourcegroup>",
"subscriptionid": "<subscriptionid>",
"cosmosdbkey": "<primary | secondary>",
"keyvaultname": "<keyvaultname>"
}
```
