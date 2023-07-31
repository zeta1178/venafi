#lambda name: importVenafiCert
#layers: requests, pyOpenSSL

import json
import requests
import warnings
import os
import boto3
import base64
import subprocess
import logging
import time
from OpenSSL import crypto
import smgr

logger=logging.getLogger()
logger.setLevel(logging.INFO)

acm_client = boto3.client('acm')
s3Client = boto3.client('s3')
s3bucket = 'my-bucket'

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

    #get Venafi Cert
    token_url='https://<venafi url here>:443/vedauth/authorize/oauth'
    #get Individual Cert from guid
    #cert_url  ='https://<venafi url here>:443/vedsdk/certificates/'
    #get all list of certs
    #certs_url ='https://<venafi url here>:443/vedsdk/certificates/retrieve?'
    
    user = (smgr.secret_function())[0]
    password = (smgr.secret_function())[1]
    
    # domain = os.environ['domain']
    # username = os.environ['user']
    # passwrd = os.environ['pass']
    CertDN = os.environ['CertificateLocation']
    certs = os.environ['cert']

    creds={
        'client_id' : 'client-certificate-auth',
        #'username' : domain+'\\'+username,
        'username' : user,
        'password' : password,
        'scope' : 'certificate:discover,manage,delete'
    }
    
    headers = {
        "Content-Type":"application/json"
              } 
    
    warnings.filterwarnings("ignore")
    #returns the Venafi Token
    response_token =requests.post(token_url, headers=headers, json=creds, verify=False).text
    response_token_formatted = json.loads(response_token)
    #return response_formatted
   
    token = response_token_formatted['access_token']
    #print(token)
    
    
    headerz = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/x-pkcs12',
    }
    
    #return an individual Cert
    guid='{xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx}'
    cert_url  ='https://<venafi url here>:443/vedsdk/certificates/'
    #response_cert =requests.get(cert_url+guid, headers=headerz, verify=False).text
    #response_cert_formatted =json.loads(response_cert)
    #return response_cert_formatted
    
    
    #return a list of Cert
    headerz2 = {
    'Authorization': 'Bearer ' + token,
    #'Content-Type': 'application/json',
    #'Content-Type': 'application/x-pkcs12'
    'Content-Type': 'application/x-pem'
    }
    
    payload = {
        "CertificateDN" : CertDN+certs,
        "Format": "Base64", 
        #"Format": "PKCS #12",
        "IncludeChain" : "true",
        "Password" : "<temp password here>",
        "IncludePrivateKey" : "true",
        "RootFirstOrder" : "true"
    }
    certs_url ='https://<venafi url here>:443/vedsdk/certificates/retrieve?'
    response_certs = requests.get(certs_url, headers=headerz2, params=payload, verify=False).text
    #response_certs = (requests.get(certs_url, headers=headerz2, params=payload, verify=False).content) 
    startcertificatebody = response_certs.find('subject=CN='+certs)
    startprivateKey = response_certs.find('-----BEGIN RSA PRIVATE KEY-----')
    #print(response_certs)
    #return response_certs
    
    
    #Certificate Combined
    cert=response_certs
    
    #CertificateChain
    certChain=response_certs[0:startcertificatebody]
    #print(certChain)
    
    #CertificateBody
    certBody=response_certs[(startcertificatebody):startprivateKey]
    #print(certBody)
    
    #PrivateKey
    certPK=response_certs[(startprivateKey):]
    #print(certPK)
    
    
    '''
    tmp=base64.b64decode(cert)
    print(tmp)
    '''
    
    
    cert_path = '/tmp/cert.pem' 
    with open(cert_path, 'w') as fp:
        fp.write(cert)
    fileName_cert = 'cert.pem' 
    s3Client.upload_file(cert_path, s3bucket, 'venafi/'+fileName_cert)
    
    
    
    cert_chain_path = '/tmp/cert_chain.pem'
    with open(cert_chain_path, 'w') as fp:
        fp.write(certChain)
    fileName_cert_chain = 'cert_chain.pem' 
    s3Client.upload_file(cert_chain_path, s3bucket, 'venafi/'+fileName_cert_chain)
    
    cert_body_path = '/tmp/cert_body.pem'
    with open(cert_body_path, 'w') as fp: 
        fp.write(certBody)
    fileName_cert_body = 'cert_body.pem' 
    s3Client.upload_file(cert_body_path, s3bucket, 'venafi/'+fileName_cert_body)
    
    cert_pk_path = '/tmp/cert_pk.pem'
    with open(cert_pk_path, 'w') as fp: 
        fp.write(certPK)
    fileName_cert_pk = 'cert_pk.pem' 
    s3Client.upload_file(cert_pk_path, s3bucket, 'venafi/'+fileName_cert_pk)
    
    #tmp=openSSL rsa -in cert_pk_path -nocerts -out '/tmp/cert_pk2.pem'
    pk_pem = crypto.load_privatekey(crypto.FILETYPE_PEM, open('/tmp/cert_pk.pem', 'rb').read(), b'<temp password here>')
    #print(crypto.dump_privatekey(crypto.FILETYPE_PEM, pk_pem))
     
    #run_command("/opt/aws s3 ls;")
    #run_command("/opt/aws acm list-certificates;")
    #run_command('/opt/aws acm import-certificate --certificate file://'+cert_body_path+' --certificate-chain file://'+cert_chain_path+' --private-key file://'+cert_pk_path+';')
    
    
    
    #import ACM cert (preferred LM Method)
    #"errorMessage": "An error occurred (ValidationException) when calling the ImportCertificate operation: Passed PEM was not a private key."
    response_ACM_cert = acm_client.import_certificate(
        Certificate=bytes(certBody, 'utf-8'),
        PrivateKey=crypto.dump_privatekey(crypto.FILETYPE_PEM, pk_pem),
        CertificateChain=bytes(certChain, 'utf-8')
        )
    return response_ACM_cert
