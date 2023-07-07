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

import json
import ast

from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.api import POSTData, PATCHData, POSTWithoutData
from ansible_collections.thalesgroup.ciphertrust.plugins.module_utils.exceptions import CMApiException, AnsibleCMException

def createLocalCA(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key != "node" and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      __resp = POSTData(
          payload=payload,
          cm_node=kwargs['node'],
          cm_api_endpoint="ca/local-cas",
          id="id",
        )
      
      return ast.literal_eval(str(__resp))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def updateLocalCA(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = PATCHData(
            payload=payload,
            cm_node=kwargs['node'],
            cm_api_endpoint="ca/local-cas/" + kwargs['id'],
        )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def selfSign(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = POSTData(
          payload=payload,
          cm_node=kwargs['node'],
          cm_api_endpoint="ca/local-cas/" + kwargs['id'] + "/self-sign",
          id="id",
        )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def issueCertificate(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = POSTData(
          payload=payload,
          cm_node=kwargs['node'],
          cm_api_endpoint="ca/local-cas/" + kwargs['id'] + "/certs",
          id="id",
        )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def revokeCert(**kwargs):
    request = {}

    for key, value in kwargs.items():
        if key not in ["node", "id", "cert_id"] and value != None:
            request[key] = value

    payload = json.dumps(request)

    try:
      response = POSTData(
          payload=payload,
          cm_node=kwargs['node'],
          cm_api_endpoint="ca/local-cas/" + kwargs['id'] + "/certs/" + kwargs['cert_id'] + "/revoke",
          id="id",
        )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise

def resumeCert(**kwargs):
    try:
      response = POSTWithoutData(
          cm_node=kwargs['node'],
          cm_api_endpoint="ca/local-cas/" + kwargs['id'] + "/certs/" + kwargs['cert_id'] + "/resume",
        )
      return ast.literal_eval(str(response))
    except CMApiException as api_e:
      raise
    except AnsibleCMException as custom_e:
      raise