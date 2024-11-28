# demo with generated OpenAPI stubs
# generate with:
# openapi-generator-cli generate -i https://raw.githubusercontent.com/suva-ch/risk-api/refs/heads/main/tarifierung-api.yaml -g python -o gen

import pathlib

if True: # add stubs to module search path
    import sys
    GEN = pathlib.Path('gen')
    if not GEN.exists(): raise Exception('run openapi-generator-cli ...')
    sys.path.append(str(GEN.absolute()))

import logging
import requests
from configparser import ConfigParser
import jwt  # PyJWT
import time
import uuid
import json
from typing import Dict, List, Optional, Any

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger()

config = ConfigParser()


def getAccessToken() -> Optional[str]:

    # Token request details
    token_data = {
        'grant_type': 'client_credentials',
        'client_id': config['Credentials']['ClientID'],
        'client_secret': config['Credentials']['ClientSecret'],
    }

    try:
        log.info('Sending POST request to retrieve token to %s', config['Credentials']['TokenURL'])
        log.debug('data=%s', token_data)
        response = requests.post(config['Credentials']['TokenURL'],
                                 data=token_data,
                                 headers={'User-Agent': config['Client']['User-Agent']}
                                 )
        response.raise_for_status()
        token_response = response.json()
        token = token_response.get('access_token')
        if not token:
            log.error('Access token not found in the response.')
            return None
        log.info('Access token retrieved successfully.')
        return token
    except Exception as e:
        log.exception('Failed to retrieve token')
        return None


def getAccessTokenJWT() -> Optional[str]:

    claims = {
        'iss': config['Credentials']['ClientID'],
        'sub': config['Credentials']['ClientID'],
        'jti': str(uuid.uuid4()),
        'aud': config['Credentials']['JWTAudience'],
        'iat': int(time.time()),
        'exp': int(time.time() + 300)  # 300 seconds
    }

    encoded_jwt = jwt.encode(claims, config['Credentials']['ClientSecret'], algorithm='HS256')  # FIXME

    # Token request details
    token_data = {
        'grant_type': 'client_credentials',
        'client_assertion_type': 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        'client_assertion': encoded_jwt
    }

    try:
        log.info('Sending POST request to retrieve token to %s', config['Credentials']['TokenURL'])
        log.debug('data=%s', token_data)
        response = requests.post(config['Credentials']['TokenURL'],
                                 data=token_data,
                                 headers={'User-Agent': config['Client']['User-Agent']}
                                 )
        response.raise_for_status()
        token_response = response.json()
        token = token_response.get('access_token')
        if not token:
            log.error('Access token not found in the response.')
            return None
        log.info('Access token retrieved successfully.')
        return token
    except Exception as e:
        log.exception('Failed to retrieve token')
        return None


def main() -> None:
    config_file = pathlib.Path('config.ini')
    if not config_file.exists(): raise Exception('config.ini is missing')
    config.read(config_file)

    from openapi_client.api_client import ApiClient
    from openapi_client.configuration import Configuration
    api_config = Configuration()

    if config['Credentials'].getboolean('UseSignedJWT', False):
        api_config.access_token = getAccessTokenJWT()
    else:
        api_config.access_token = getAccessToken()

    if api_config.access_token is None:
        log.error('no access token')
        return

    log.info('AccessToken=%s...', api_config.access_token[0:5])

    api_config.host = config['API']['OccupationCodesBaseURL']

    client = ApiClient(configuration=api_config)
    client.default_headers['User-Agent'] = config['Client']['User-Agent']
    client.default_headers['Authorization'] = 'Bearer ' + api_config.access_token  # see https://github.com/OpenAPITools/openapi-generator/issues/18041

    x_headers: Dict[str, Any] = {
        'x_client_vendor': config['Client']['X-Client-Vendor'],
        'x_client_name': config['Client']['X-Client-Name'],
        'x_client_version': config['Client']['X-Client-Version'],
    }

    def demoListaOccupationCodes() -> None:
        from openapi_client.api.suva_occupation_codes_api import SuvaOccupationCodesApi
        from openapi_client.models.suva_occupation_code import SuvaOccupationCode
        api = SuvaOccupationCodesApi(api_client=client)
        res: List[SuvaOccupationCode] = api.get_suva_occupation_codes()
        log.info('received %i codes', len(res))

    demoListaOccupationCodes()

    def demoOperatingUnits() -> None:
        from openapi_client.api.occupation_codes_api import OccupationCodesApi

        api = OccupationCodesApi(api_client=client)

        res = api.get_operating_unit_profiles(**x_headers, year=2025)
        print(res)

    # demoOperatingUnits() # not implemented yet

    def demoSubmit() -> None:
        from openapi_client.api.occupation_codes_api import OccupationCodesApi
        from openapi_client.exceptions import NotFoundException
        from openapi_client.models.submit_occupation_code import SubmitOccupationCode, OccupationDescription
        from openapi_client.models.language import Language
        from openapi_client.models.gender import Gender

        api = OccupationCodesApi(api_client=client)

        desc = OccupationDescription(language=Language.DE, gender=Gender.MALE, value='Zauberlehrling')
        code = SubmitOccupationCode(occupationCodeNr1='', occupationCodeNr2='', preferredLanguage=Language.DE, descriptions=[desc])
        try:
            res = api.submit_occupation_code(**x_headers, submit_occupation_code=code)
            print(res)
        except NotFoundException as nfe:
            body = json.loads(str(nfe.body))
            log.error('NotFoundException:%s', body['message'])

    demoSubmit()


if __name__ == '__main__':
    main()
