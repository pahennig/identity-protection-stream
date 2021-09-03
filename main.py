from flow import az_flow

if __name__ == '__main__':
    #AZ Identity Protection feed
    azure = az_flow.AzureManagement()

    #Interaction with SIEM
    findings = azure.finding_handler('Azure Identity Protection Finding')