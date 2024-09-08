import os
import validators
from urllib.parse import urlparse
from enum import Enum
import re
import requests

# python -m unittest discover -s tests

class TargetType(Enum):
    DIRECTORY = 'directory'
    GITHUB = 'github'
    WEB = 'web'
    OPENAPI = 'openapi'
    GRAPHQL = 'graphql'
    SOAP = 'soap'
    DOCKER = 'docker'

    @staticmethod
    def is_soap_endpoint(url):
        try:
            wsdl_url = f"{url}?wsdl" if  not url.endswith("?wsdl") else url
            response = requests.get(wsdl_url)
            if response.status_code == 200 and 'definitions' in response.text:
                return True
            return False
        except requests.exceptions.RequestException as e:
            print(f"An error occurred: {e}")
            return False

    @staticmethod
    def get_target_type(target):
        if validators.url(target):
            if urlparse(target).netloc=="github.com":
                return TargetType.GITHUB
            else:
                try:
                    response = requests.get(target)
                    content = response.text
                    if '"openapi"' in content or '"swagger"' in content:
                        return TargetType.OPENAPI
                    elif TargetType.is_soap_endpoint(target):
                        return TargetType.SOAP
                    # elif '<soapenv:Envelope' in content or 'xmlns:soapenv' in content:
                    #     return TargetType.SOAP
                    else:
                        introspection_query = {"query": "{ __schema { types { name } } }"}
                        introspection_response = requests.post(target, json=introspection_query)
                        if introspection_response.status_code == 200 and '__schema' in introspection_response.text:
                            return TargetType.GRAPHQL
                        else:
                            return TargetType.WEB
                except requests.exceptions.RequestException as e:
                    return TargetType.WEB
        elif os.path.exists(target):
            return TargetType.DIRECTORY
        elif re.match(r'^(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)?[a-z0-9]+(?:[._-][a-z0-9]+)*(?::[a-zA-Z0-9._-]+|@[A-Za-z0-9:]+)?$', target):
            #TODO add image check in registry
            return TargetType.DOCKER
        else:
            return None