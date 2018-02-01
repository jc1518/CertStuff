#!/usr/bin/env python3

"""
Akamai CPS client
Reference https://developer.akamai.com/api/luna/siteshield/overview.html
"""

import requests
import json
from akamai.edgegrid import EdgeGridAuth


class Client(object):

    def __init__(self, base_url, client_token, client_secret, access_token):
        """Authentication"""
        self.base_url = base_url
        self.client_token = client_token
        self.client_secret = client_secret
        self.access_token = access_token
        self.session = requests.Session()
        self.session.auth = EdgeGridAuth(
            client_token=self.client_token,
            client_secret=self.client_secret,
            access_token=self.access_token,
            max_body=128 * 1024
        )

    def list_enrollments(self, contract_id):
        """Get enrollments ID"""
        enrollments_id = []
        response = self.session.get(self.base_url+'/cps/v2/enrollments?contractId='+contract_id,
                                       headers={'Accept': 'application/vnd.akamai.cps.enrollments.v4+json'})
        enrollments = json.loads(response.text)
        for enrollment in enrollments['enrollments']:
            enrollments_id.append(enrollment['location'])
        print('Enrollment ID in', contract_id, enrollments_id)
        return enrollments_id

    def get_prod_deployment(self, enrollment_id):
        """Get prod deployment of enrollment id"""
        response = self.session.get(self.base_url+enrollment_id+'/deployments/production',
                                      headers={'Accept': 'application/vnd.akamai.cps.deployment.v3+json'})
        deployment = json.loads(response.text)
        return deployment

    def get_cert(self, deployment):
        """Extract cert from deployment"""
        cert = deployment["certificate"]
        return cert





