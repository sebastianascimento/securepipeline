from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential

def get_secret(secret_name: str) -> str:
    vault_url = "https://secpipelinesebakv.vault.azure.net/"
    client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
    return client.get_secret(secret_name).value