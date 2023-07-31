#lambda name: saveVenafiCert

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

logger=logging.getLogger()
logger.setLevel(logging.INFO)

acm_client = boto3.client('acm')
# reference: https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/acm.html#ACM.Client.import_certificate

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
    
    #pull in secret and password for the SVC ACCT CONNECTED TO VENAFI ACCOUNT
    user = (smgr.secret_function())[0]
    password = (smgr.secret_function())[1]

    ############################################################################
    # GET VENAFI TOKEN
    ############################################################################
    
    token_url='https://<venafi url here>:443/vedauth/authorize/oauth'
    
    CertDN = os.environ['CertificateLocation']
    certs = os.environ['cert']

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
    response_token =requests.post(token_url, headers=headers, json=creds, verify=False).text
    response_token_formatted = json.loads(response_token)
    #return response_formatted
   
    token = response_token_formatted['access_token']
    #print(token)
    
    ############################################################################
    # GET VENAFI CERTIFICATE
    ############################################################################
    
    headerz = {
    'Authorization': 'Bearer ' + token,
    'Content-Type': 'application/x-pkcs12',
    }
    
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
    #return response_certs
    
    ############################################################################
    # GET CERTIFICATE BODY, KEY AND CHAIN
    ############################################################################
    
    startcert = "\r\n-----BEGIN CERTIFICATE-----\r\n"
    endcert = "\r\n-----END CERTIFICATE-----\r\n"
    
    certChainGuts1 = ((response_certs.split(startcert))[1].split(endcert)[0])
    certChain1 = startcert + certChainGuts1 + endcert
    # print('This is cert chain1')
    # print(certChain1)
    
    certChainGuts2 = ((response_certs.split(startcert))[2].split(endcert)[0])
    certChain2 = startcert + certChainGuts2 + endcert
    # print('This is cert chain2')
    # print(certChain2)
    
    fullcertchain = certChain1 + certChain2
    # print('This is the fullcertchain')
    # print(fullcertchain)
    
    certBodyGuts = ((response_certs.split(startcert))[3].split(endcert)[0])
    certBody = startcert + certBodyGuts + endcert
    # print('This is the cert body')
    # print(certBody)
    
    startPrivateKey = "\r\n-----BEGIN RSA PRIVATE KEY-----\r\n"
    endPrivateKey = "\r\n-----END RSA PRIVATE KEY-----\r\n\r\n"
    
    privateKeyGuts = ((response_certs.split(startPrivateKey))[1].split(endPrivateKey)[0])
    cert_pk = startPrivateKey + privateKeyGuts + endPrivateKey
    # print('This is the privateKey')
    # print(cert_pk)

    ############################################################################
    # IMPORT CERTIFICATE INTO AMAZON CERTIFICATE MANAGER (ACM)
    ############################################################################
    
    #reference: https://docs.aws.amazon.com/code-samples/latest/catalog/code-catalog-python-example_code-acm.html
    
    # def import_certificate (fullcertchain, certBody, privatekey):
    #     try:
    #         response = acm_client.import_certificate(
    #             CertificateChain=fullcertchain, Certificate=certBody, PrivateKey=privatekey)
    #         certificate_arn = response['CertificateArn']
    #         logger.info("Imported certificate.")
    #     except ClientError:
    #         logger.exception("Couldn't import certificate.")
    #         raise
    #     else:
    #         return certificate_arn
    cert_pk_path = '/tmp/cert_pk.pem'
    with open(cert_pk_path, 'w') as fp: 
        fp.write(cert_pk)
    fileName_cert_pk = 'cert_pk.pem' 
    #NOTE: password listed below is just for test. future implementation will use Secrets Mgr to retrieve certificate passwords
    pk_pem = crypto.load_privatekey(crypto.FILETYPE_PEM, open('/tmp/cert_pk.pem', 'rb').read(), b'<temp password here>')
    response_ACM_cert = acm_client.import_certificate(
        Certificate=bytes(certBody, 'utf-8'),
        PrivateKey=crypto.dump_privatekey(crypto.FILETYPE_PEM, pk_pem),
        CertificateChain=bytes(fullcertchain, 'utf-8')
    )

