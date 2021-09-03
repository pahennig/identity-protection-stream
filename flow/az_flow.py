import datetime
from flow.vault import VaultManagement
import requests
import os
from dotenv import load_dotenv
import json
import flow.customrsyslog as customrsyslog

# Initialize vault client
load_dotenv()
ROLE_ID = os.getenv('VAULT_ROLE_ID')
SECRET_ID = os.getenv('VAULT_SECRET_ID')
vault_request = VaultManagement(
    'https://$VAULT_URL',
    ROLE_ID,
    SECRET_ID
    )

#KV get client_id and client_secret
CLIENT_ID, CLIENT_SECRET = vault_request.get_data('$VAULT_MOUNT', '$VAULT_PATH')


SCOPE = "https://graph.microsoft.com/.default"
GRANT_TYPE = "client_credentials"
URI="https://login.microsoftonline.com/$TENANT_ID/oauth2/v2.0/token"


class AzureManagement:
    token_data = {
    'grant_type': GRANT_TYPE,
    'client_id': CLIENT_ID,
    'client_secret': CLIENT_SECRET,
    'scope': 'https://graph.microsoft.com/.default',
    }

    def get_token(self,uri, data=token_data):
        """
            Authentication with client_secret, obtaining JWT
        """

        self.uri = uri
        self.data = data
        
        token_request = requests.post(self.uri, data=self.token_data)
        token = token_request.json().get('access_token')
        return (f"Bearer {token}")

    @staticmethod
    def timestamp():
        """
            Return last 24 hours timestamp
        """
        now = datetime.datetime.now() - datetime.timedelta(days=1)
        return now.strftime("%Y-%m-%dT%H:%M:%SZ")

    def risk_detection(self, graph_url='https://graph.microsoft.com/', query_parameter=None, operator=None, sort=None):
        """
            URI constructor
        """
        self.query_parameter = query_parameter
        self.operator = operator
        self.graph_url = graph_url
        self.jwt = self.get_token(uri=URI)

        get_method = (f"{self.graph_url}/{query_parameter} {operator} {AzureManagement.timestamp()}{sort}")
        header = {
        'Authorization': self.jwt
        }
        return json.loads(requests.get(get_method, headers=header).text)

    def formatter(self):
        """
            Query parameter, returning list of findings
        """
        self.data_list = []
        response = self.risk_detection(
            query_parameter='beta/riskDetections?$filter=detectedDateTime',
            operator='ge',
            sort='&orderby=detectedDateTime desc'
            )

        for entry in response['value']:
            self.data_list.append(
                {
                "detectedDateTime" : entry['detectedDateTime'],
                "affectedUser" : entry['userPrincipalName'],
                "riskEventType" : entry['riskEventType'],
                "sourceIP" : entry['ipAddress'],
                "user_agent" : entry['additionalInfo'],
                "location" : entry['location']
                })
        return self.data_list

    def finding_handler(self, name):
        """
            Sending events to SIEM
        """
        self.name = name
        self.findings = self.formatter()
        self.siem_logger = customrsyslog.rfc5434_logger(self.name)

        for finding in self.findings:
            self.siem_logger.info(json.dumps(finding))
            print(json.dumps(finding))