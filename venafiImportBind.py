#lambda name: VenafiImportBind
#layers: requests, pyOpenSSL

import json
import requests
import warnings
import os
import smgr
import boto3
import base64
import subprocess
import logging
import time
from OpenSSL import crypto
import re
import smgr

logger=logging.getLogger()
logger.setLevel(logging.INFO)

s3Client = boto3.client('s3')
s3bucket = 'my-bucket'
ssm = boto3.client('ssm')

def run_command(command):
    try:
        #logger.info("Running shell command: \"{}\"".format(command))
        result = subprocess.run(command, stdout=subprocess.PIPE, shell=True);
        logger.info("Command Output:\n---\n{}\n---".format(result.stdout.decode('UTF-8')))
    except Exception as e:
        logger.error("Exception: {}".format(e))
        return False
    return True
     
def lambda_handler(event, context):
     
    # Pull in secret and password for the SVC ACCT CONNECTED TO VENAFI ACCOUNT
    user = (smgr.secret_function())[0]
    password = (smgr.secret_function())[1]
     
    ############################################################################
    # GET VENAFI TOKEN
    ############################################################################
     
    token_url='https://<certURLhere>:443/vedauth/authorize/oauth'
     
    CertDN = '\\VED\\Policy\\Certificates\\<LOCATIONS HERE>\\'
    certs = 'diana.us.com'

    creds={
        'client_id' : 'client-certificate-auth',
        'username' : user,
        'password' : password,
        'scope' : 'certificate:discover,manage,delete'
    }
     
    headers = {
        "Content-Type":"application/json"
    }
     
    warnings.filterwarnings("ignore")
    #returns the Venafi Token
    response_token = requests.post(token_url, headers=headers, json=creds, verify=False).json()
    
    token = response_token['access_token']

    ############################################################################
    # GET VENAFI CERTIFICATE
    ############################################################################
     
    headerz = {
        'Content-Type': 'application/json',
        'X-Venafi-Api-Key': token,
    }
     
    payload = {
        "CertificateDN" : CertDN+certs,
        "Format": "PKCS #12",
        "IncludeChain" : "true",
        "Password" : event['password'],
        "IncludePrivateKey" : "true",
        "RootFirstOrder" : "true"
    }
    certs_url ='https://<venafi url here>:443/vedsdk/certificates/retrieve'
    response_certs = requests.post(certs_url, headers=headerz, json=payload, verify=False).json()
     
    if 'Error' in response_certs:
        return {
            'errorMessage': response_certs['Error']
        }
     
    ############################################################################
    # Parse cert output
    ############################################################################
     
    # CertificateData is encoded as base64 (which we want anyway)
    cert_encoded = response_certs["CertificateData"]
    file_name = str(response_certs["Filename"])
     
    ############################################################################
    # Get thumbprint
    ############################################################################
     
    pfx = crypto.load_pkcs12(base64.b64decode(cert_encoded), event['password'])
    thumbprint = pfx.get_certificate().digest('sha1').decode('utf8').replace(':', '')
     
    ############################################################################
    # PUSH VENAFI CERTIFICATE TO SERVER
    ############################################################################
     
    managedList= ssm.describe_instance_information(
            Filters=[
        {
            'Key': 'ResourceType',
            'Values': [
                'ManagedInstance',
            ],
            'Key': 'tag:NameTag',
            'Values' : [event['server']]
        },
    ]
    )['InstanceInformationList']

    managedList3=[]
    for item in managedList:
        managedList3.append(str(item['InstanceId']))
         
    cmd = ('$destPath = "C:\\Temp\\%s";' % file_name + # Set dest path of the cert
        '$cert_encoded = "' + cert_encoded + '";' + # Set cert_encoded = base 64 encoding of cert
        '$cert_bytes = [System.Convert]::FromBase64CharArray($cert_encoded, 0, $cert_encoded.Length);'+ # Convert base64 to bytes
        'Set-Content $destPath -Value $cert_bytes -Encoding Byte;'+ # Put the cert file at the destination
        'Import-PfxCertificate –FilePath $destPath Cert:\LocalMachine\My -Password (ConvertTo-SecureString -String "%s" -Force –AsPlainText) -Exportable:$true;' % event['password'] + # Import the cert
        '$NewCert = Get-ChildItem -Path Cert:\LocalMachine\My |?{$_.Thumbprint -match "%s"};' % thumbprint + # Get the imported cert
        '$SPiis = Get-WebBinding -name %s -Protocol https;' % (event['iis-site'])+ # Find the IIS site to attach cert to
        '$SPiis.AddSslCertificate($NewCert.GetCertHashString(), "my");'+ # Add cert to site
        'Remove-Item $destPath' # Remove cert file
    )
     
    ssm_out = ssm.send_command(
        InstanceIds=managedList3,
        DocumentName='AWS-RunPowerShellScript',
        TimeoutSeconds=900,
        Parameters={
            'commands': [
                cmd
            ]
        }
    )
    # User needs to know the thumbprint and the command id to verify that it was successful
    return {
        'thumb': thumbprint,
        'ssm_cmd': ssm_out['Command']['CommandId']
    }
