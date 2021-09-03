import hvac
from dotenv import load_dotenv
import os

load_dotenv()
ROLE_ID = os.getenv('VAULT_ROLE_ID')
SECRET_ID = os.getenv('VAULT_SECRET_ID')


class VaultManagement:
    def __init__(self, vault_addr, role_id, secret_id):
        """
            Constructing app role authentication
        """
        self.vault_addr = vault_addr
        self.role_id = role_id
        self.secret_id = secret_id

        self.client = hvac.Client(self.vault_addr)
        self.client.auth.approle.login(
            role_id=self.role_id,
            secret_id=self.secret_id
        )

    def get_data(self, path, mount_point):
        """
            KV get client_id and client_secret
        """
        self.path = path
        self.mount_point = mount_point

        secret_response = self.client.secrets.kv.v1.read_secret(
            path=self.path,
            mount_point=self.mount_point
        )
        return (secret_response['data']['client_id'], secret_response['data']['client_secret'])