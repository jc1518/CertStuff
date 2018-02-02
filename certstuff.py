#!/usr/bin/env python3

"""
01/02/2018 Jackie Chen - CertStuff Version 1.0
    - Check AWS IAM imported certs
    - Check AWS ACM issued certs
    - Check Akamai production certs
"""

# TODO: Add expire date reminder

import boto3
import argparse
import cps
import os
import re
import datetime
import pytz
from tzlocal import get_localzone
from OpenSSL import crypto
from ndg.httpsclient.subj_alt_name import SubjectAltName as BaseSubjectAltName
from pyasn1.codec.der.decoder import decoder as der_decoder
from pyasn1.type import univ, constraint
from json2html import *
import webbrowser


def list_regions():
    """Get all AWS regions"""
    ec2_client = boto3.client('ec2', region_name='us-east-1')
    response = ec2_client.describe_regions()
    return response['Regions']


def list_acm_cert():
    """Get certs arn from ACM"""
    acm_certs = acm_client.list_certificates(CertificateStatuses=['ISSUED'])
    acm_certs_arn = []
    for cert in acm_certs['CertificateSummaryList']:
        acm_certs_arn.append(cert['CertificateArn'])
    return acm_certs_arn


def describe_acm_cert(arn):
    """Read ACM cert info"""
    acm_cert = acm_client.describe_certificate(CertificateArn=arn)
    acm_cert_info = [
        acm_cert['Certificate']['DomainName'],
        acm_cert['Certificate']['SubjectAlternativeNames'],
        acm_cert['Certificate']['Issuer'],
        acm_cert['Certificate']['NotAfter']
    ]
    return acm_cert_info


def list_iam_cert():
    """Get certs name from IAM"""
    response = iam_client.list_server_certificates(
        MaxItems=123
    )
    iam_certs = response['ServerCertificateMetadataList']
    return iam_certs


def describe_iam_cert(name):
    """Extract pem cert"""
    iam_cert = iam_client.get_server_certificate(ServerCertificateName=name)
    iam_cert_body = iam_cert['ServerCertificate']['CertificateBody']
    return iam_cert_body


def time_converter(time):
    """Convert ASN1 time format to human readable"""
    regex = re.compile(
        r'(?P<year>(\d){4})'
        r'(?P<month>(\d){2})'
        r'(?P<day>(\d){2})'
        r'(?P<hour>(\d){2})'
        r'(?P<minute>(\d){2})'
        r'(?P<second>(\d){2})Z'
    )
    match = regex.match(time)
    utc_time = datetime.datetime(int(match['year']), int(match['month']), int(match['day']),
                           int(match['hour']), int(match['minute']), int(match['second']),
                           tzinfo=pytz.utc)
    local_time = utc_time.astimezone(get_localzone())
    return local_time


def decode_cert(cert):
    """
    Decode pem cert
    Reference: https://github.com/requests/requests-docs-it/blob/master/requests/packages/urllib3/contrib/pyopenssl.py
    """

    class SubjectAltName(BaseSubjectAltName):
        """
        ASN.1 implementation for subjectAltNames support
        This is a slightly bug-fixed version of same from ndg-httpsclient.
        There is no limit to how many SAN certificates a certificate may have,
        however this needs to have some limit so we'll set an arbitrarily high
        limit.
        """
        sizeSpec = univ.SequenceOf.sizeSpec + constraint.ValueSizeConstraint(1, 1024)

    san = []
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    for i in range(cert.get_extension_count()):
        ext = cert.get_extension(i)
        ext_name = ext.get_short_name()
        general_names = SubjectAltName()
        if ext_name.decode('utf8') == 'subjectAltName':
            ext_dat = ext.get_data()
            decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)
            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        if component.getName() != 'dNSName':
                            continue
                        san.append(str(component.getComponent()))
    expire_date = time_converter(cert.get_notAfter().decode('utf8'))
    decoded_cert = [cert.get_subject().commonName, san, cert.get_issuer().commonName, expire_date]
    return decoded_cert


def get_akamai_cert(contract_id, base_url, client_token, client_secret, access_token):
    """Get Akamai production cert"""
    certs = []
    cps_client = cps.Client(base_url, client_token, client_secret, access_token)
    print('------- Checking cert in Akamai contract', contract_id, '-------')
    enrollments = cps_client.list_enrollments(contract_id)
    for enrollment_id in enrollments:
        cert = cps_client.get_cert(cps_client.get_prod_deployment(enrollment_id))
        certs.append(cert)
    cert_info = [{'contract': contract_id, 'certs': certs}]
    return cert_info


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--aws', help='List issued certificates in AWS',
                        action='store_true')
    parser.add_argument('--akamai', help='List production certificates in Akamai',
                        action='store_true')
    args = parser.parse_args()
    all_certs = []
    n = 1
    if args.aws:
        regions = list_regions()
        for region in regions:
            # AWS credentials are passed from environment variables
            acm_client = boto3.client('acm', region_name=region['RegionName'])
            iam_client = boto3.client('iam', region_name=region['RegionName'])

            print('------ACM CERT-', region['RegionName'], '---------------------------')
            for arn in list_acm_cert():
                acm_cert = describe_acm_cert(arn)
                print(acm_cert)
                acm_cert_json = {
                    "ID": n,
                    "Common Name": acm_cert[0],
                    "SAN": acm_cert[1],
                    "Issuer": acm_cert[2],
                    "Expire date": acm_cert[3],
                    "Region": region['RegionName'],
                    "Type": "ACM",
                    "ARN or Name": arn
                }
                n += 1
                all_certs.append(acm_cert_json)

        print('------IAM CERT---------------------------')
        for name in list_iam_cert():
            iam_cert = decode_cert(describe_iam_cert(name['ServerCertificateName']))
            print(name['ServerCertificateName'], ':', iam_cert)
            iam_cert_json = {
                "ID": n,
                "Common Name": iam_cert[0],
                "SAN": iam_cert[1],
                "Issuer": iam_cert[2],
                "Expire date": iam_cert[3],
                "Region": "Global",
                "Type": "IAM",
                "ARN or Name": name['ServerCertificateName']
            }
            n += 1
            all_certs.append(iam_cert_json)

    if args.akamai:
        # Cedentials are passed from envrionment variables
        akamai_certs_info = get_akamai_cert(os.environ['AKAMAI_CPS1_CONTRACT_ID'], os.environ['AKAMAI_CPS_URL'],
                                           os.environ['AKAMAI_CPS_CLIENT_TOKEN'], os.environ['AKAMAI_CPS_CLIENT_SECRET'],
                                           os.environ['AKAMAI_CPS_ACCESS_TOKEN']) 

        for cert_info in akamai_certs_info:
            # Get Akamai certs
            for cert in cert_info['certs']:
                akamai_cert = decode_cert(cert)
                akamai_cert_json = {
                    "ID": n,
                    "Common Name": akamai_cert[0],
                    "SAN": akamai_cert[1],
                    "Issuer": akamai_cert[2],
                    "Expire date": akamai_cert[3],
                    "Region": "N/A",
                    "Type": "Akamai",
                    "ARN or Name": akamai_cert[0]
                }
                n += 1
                all_certs.append(akamai_cert_json)

    if not args.akamai and not args.aws:
        print("You need to specify '--aws' or '--akamai' or both")
        sys.exit()

    # Generate html report
    with open('cert_list.html', 'w') as f:
        f.write(json2html.convert(json=all_certs))
    webbrowser.open('file://' + os.path.realpath('cert_list.html'))















