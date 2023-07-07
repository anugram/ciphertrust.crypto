#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2023 Thales Group. All rights reserved.
# Author: Anurag Jain, Developer Advocate, Thales
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#  http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

from __future__ import absolute_import, division, print_function
__metaclass__ = type

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.modules import CipherTrustCryptoModule
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.ca import createLocalCA, updateLocalCA, selfSign, issueCertificate, revokeCert, resumeCert
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

DOCUMENTATION = '''
---
module: cm_local_ca
short_description: Create and manage CipherTrust Manager Local CA
description:
    - Create and edit local Certificate Authority on CipherTrust Manager
version_added: "1.0.0"
author: Anurag Jain, Developer Advocate Thales Group
options:
    localNode:
      description:
        - this holds the connection parameters required to communicate with an instance of CipherTrust Manager (CM)
        - holds IP/FQDN of the server, username, password, and port 
      required: true
      type: dict
      suboptions:
        server_ip:
          description: CM Server IP or FQDN
          type: str
          required: true
        server_private_ip:
          description: internal or private IP of the CM Server, if different from the server_ip
          type: str
          required: true
        server_port:
          description: Port on which CM server is listening
          type: int
          required: true
          default: 5432
        user:
          description: admin username of CM
          type: str
          required: true
        password:
          description: admin password of CM
          type: str
          required: true
        verify:
          description: if SSL verification is required
          type: bool
          required: true
          default: false
    op_type:
      description: Operation to be performed
      choices: [create, patch]
      required: true
      type: str
    cn:
      description: Common Name
      type: str
    algorithm:
      description: RSA or ECDSA (default) algorithms are supported. Signature algorithm (SHA512WithRSA, SHA384WithRSA, SHA256WithRSA, SHA1WithRSA, ECDSAWithSHA512, ECDSAWithSHA384, ECDSAWithSHA256) is selected based on the algorithm and size.
      type: str
    dnsNames:
      description: Subject Alternative Names (SAN) values
      type: str
    emailAddresses:
      description: E-mail addresses
      type: str
    ipAddresses:
      description: IP addresses
      type: str
    name:
      description: A unique name of CA, if not provided, will be set to localca-<id>.
      type: str
    names:
      description: Name fields
      type: list
    size:
      description: CSR in PEM format
      type: str
    allow_client_authentication:
      description: If set to true, the certificates signed by the specified CA can be used for client authentication.
      type: bool
    allow_user_authentication:
      description: If set to true, the certificates signed by the specified CA can be used for user authentication.
      type: bool
    csr:
      description: CSR in PEM format
      type: str
    purpose:
      description: server, client or ca
      type: str
    duration:
      description: Duration in days of certificate. Either duration or notAfter date must be specified.
      type: int
    notAfter:
      description: End date of certificate. Either notAfter or duration must be specified. notAfter overrides duration if both are given.
      type: str
    notBefore:
      description: Start date of certificate
      type: str
    reason:
      description: Specify one of the reason.
      choices: [unspecified, keyCompromise, cACompromise, affiliationChanged, superseded, cessationOfOperation, certificateHold, removeFromCRL, privilegeWithdrawn, aACompromise]
      type: str
'''

EXAMPLES = '''
- name: "Create CM Local CA"
  ciphertrust.crypto.cm_local_ca:
    localNode:
        server_ip: "IP/FQDN of CipherTrust Manager"
        server_private_ip: "Private IP in case that is different from above"
        server_port: 5432
        user: "CipherTrust Manager Username"
        password: "CipherTrust Manager Password"
        verify: false
    op_type: create
'''

RETURN = '''

'''

_name = dict(
  C=dict(type='int'),
  L=dict(type='str'),
  O=dict(type='str'),
  OU=dict(type='int'),
  ST=dict(type='str'),
)

argument_spec = dict(
    op_type=dict(type='str', options=[
      'create', 
      'patch',
      'issue-cert',
      'self-sign',
      'revoke-cert',
      'resume-cert',
    ], required=True),
    id=dict(type='str'),
    cert_id=dict(type='str'),
    # Add local CA
    cn=dict(type='str'),
    algorithm=dict(type='int', options=['RSA', 'ECDSA']),
    dnsNames=dict(type='list', element='str'),
    emailAddresses=dict(type='list', element='str'),
    ipAddresses=dict(type='list', element='str'),
    name=dict(type='str'),
    names=dict(type='list', element='dict', options=_name),
    size=dict(type='int'),
    # Update local CA
    allow_client_authentication=dict(type='bool'),
    allow_user_authentication=dict(type='bool'),
    # Issue cert from Local CA
    csr=dict(type='str'),
    purpose=dict(type='str', options=['server', 'client', 'ca']),
    duration=dict(type='int'),
    notAfter=dict(type='str'),
    notBefore=dict(type='str'),
    # Revoke Cert
    reason=dict(type='int', options=['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise']),
)

def validate_parameters(cm_local_ca_module):
    return True

def setup_module_object():
    module = CipherTrustCryptoModule(
        argument_spec=argument_spec,
        required_if=(
            ['op_type', 'create', ['cn']],
            ['op_type', 'patch', ['id']],
            ['op_type', 'self-sign', ['id']],
            ['op_type', 'issue-cert', ['id', 'csr', 'purpose']],
            ['op_type', 'revoke-cert', ['id', 'cert_id', 'reason']],
            ['op_type', 'resume-cert', ['id', 'cert_id']],
        ),
        mutually_exclusive=[],
        supports_check_mode=True,
    )
    return module

def main():

    global module
    
    module = setup_module_object()
    validate_parameters(
        cm_local_ca_module=module,
    )

    result = dict(
        changed=False,
    )

    if module.params.get('op_type') == 'create':
      try:
        response = createLocalCA(
          node=module.params.get('localNode'),
          cn=module.params.get('cn'),
          algorithm=module.params.get('algorithm'),
          dnsNames=module.params.get('dnsNames'),
          emailAddresses=module.params.get('emailAddresses'),
          ipAddresses=module.params.get('ipAddresses'),
          name=module.params.get('name'),
          names=module.params.get('names'),
          size=module.params.get('size'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'patch':
      try:
        response = updateLocalCA(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          allow_client_authentication=module.params.get('allow_client_authentication'),
          allow_user_authentication=module.params.get('allow_user_authentication'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'self-sign':
      try:
        response = selfSign(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          duration=module.params.get('duration'),
          notAfter=module.params.get('notAfter'),
          notBefore=module.params.get('notBefore'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'issue-cert':
      try:
        response = issueCertificate(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          csr=module.params.get('csr'),
          purpose=module.params.get('purpose'),
          duration=module.params.get('duration'),
          name=module.params.get('name'),
          notAfter=module.params.get('notAfter'),
          notBefore=module.params.get('notBefore'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'revoke-cert':
      try:
        response = revokeCert(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          cert_id=module.params.get('cert_id'),
          reason=module.params.get('reason'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    elif module.params.get('op_type') == 'resume-cert':
      try:
        response = resumeCert(
          node=module.params.get('localNode'),
          id=module.params.get('id'),
          cert_id=module.params.get('cert_id'),
        )
        result['response'] = response
      except CMApiException as api_e:
        if api_e.api_error_code:
          module.fail_json(msg="status code: " + str(api_e.api_error_code) + " message: " + api_e.message)
      except AnsibleCMException as custom_e:
        module.fail_json(msg=custom_e.message)

    else:
        module.fail_json(msg="invalid op_type")
        
    module.exit_json(**result)

if __name__ == '__main__':
    main()