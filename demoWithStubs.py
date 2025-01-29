# demo with generated OpenAPI stubs
# generate with:
# wget -O openapi-generator-cli-7.10.0.jar https://repo1.maven.org/maven2/org/openapitools/openapi-generator-cli/7.10.0/openapi-generator-cli-7.10.0.jar
# java -jar openapi-generator-cli-7.10.0.jar generate -i https://raw.githubusercontent.com/suva-ch/risk-api/refs/heads/main/berufscode-api.yaml -g python -o gen -p useOneOfDiscriminatorLookup=true

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
import uuid
import pprint
import argparse
import random

log = logging.getLogger()

MY_UUID_NAMESPACE = uuid.UUID('1712dfb0-37d0-4330-87da-4a07984955e4')

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

    encoded_jwt = jwt.encode(claims, config['Credentials']['ClientSecret'], algorithm=config['Credentials'].get('JWTAlgorithm', 'HS512'))  # FIXME

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

    api_config.host = config['API']['OccupationCodesBaseURL']

    client = ApiClient(configuration=api_config)
    client.default_headers['User-Agent'] = config['Client']['User-Agent']

    x_headers: Dict[str, Any] = {
        'x_client_vendor': config['Client']['X-Client-Vendor'],
        'x_client_name': config['Client']['X-Client-Name'],
        'x_client_version': config['Client']['X-Client-Version'],
    }

    def demoListaOccupationCodes() -> None:
        from openapi_client.api.suva_occupation_codes_api import SuvaOccupationCodesApi
        from openapi_client.models.suva_occupation_code import SuvaOccupationCode
        api = SuvaOccupationCodesApi(api_client=client)
        res: List[SuvaOccupationCode] = api.get_suva_occupation_codes(**x_headers) # suva list
        log.info('received %i codes', len(res))
        for c in res:
            print(pprint.pformat(object=json.loads(c.model_dump_json()), indent=1, width=200))

    def demoListOperatingUnits() -> None:
        from openapi_client.api.occupation_codes_api import OccupationCodesApi
        from openapi_client.models.operating_unit_profile import OperatingUnitProfile

        api = OccupationCodesApi(api_client=client)

        res = api.get_operating_unit_profiles(**x_headers, year=2025)
        c : OperatingUnitProfile
        for c in res:
            print(pprint.pformat(object=json.loads(c.model_dump_json()), indent=1, width=200))

    def demoClearAllEvents()->None:
        from openapi_client.api.events_api import EventsApi
        from openapi_client.models.event import Event
        from openapi_client.models.event_occupation_code_submitted import EventOccupationCodeSubmitted

        api_ev = EventsApi(api_client=client)

        # clear old events
        events : List[Event] = api_ev.get_events(**x_headers)
        if len(events) == 0:
            log.info('no events')
        for e in events:
            log.info('pending event:%s', e.id)
            if e.detail is not None:
                if isinstance(e.detail.actual_instance, EventOccupationCodeSubmitted):
                    d : EventOccupationCodeSubmitted = e.detail.actual_instance
                    log.info('EventOccupationCodeSubmitted=%s', d)
            if e.id is not None:
                api_ev.acknowledge_event(**x_headers, event_id=e.id)

    def demoActivateSuvaCode() -> None:
        from openapi_client.api.suva_occupation_codes_api import SuvaOccupationCodesApi
        from openapi_client.api.occupation_codes_api import OccupationCodesApi
        from openapi_client.models.suva_occupation_code import SuvaOccupationCode
        from openapi_client.models.occupation_code_activation import OccupationCodeActivation
        from openapi_client.models.occupation_code import OccupationCode

        api_list = SuvaOccupationCodesApi(api_client=client)
        res_list: List[SuvaOccupationCode] = api_list.get_suva_occupation_codes(**x_headers)
        log.info('received %i codes', len(res_list))
        code = res_list[random.randint(0, len(res_list)-1)]
        log.info('code=%s description=%s', code.id, code.descriptions[0].model_dump_json())

        api_oc = OccupationCodesApi(api_client=client)
        activate_code = OccupationCodeActivation(suvaOccupationCodeId=code.id)
        res_activate = api_oc.activate_occupation_code(occupation_code_activation=activate_code, **x_headers)
        print(pprint.pformat(object=json.loads(res_activate.model_dump_json()), indent=1, width=200))

    def demoInActivateCode() -> None:
        from openapi_client.api.occupation_codes_api import OccupationCodesApi
        from openapi_client.models.occupation_code import OccupationCode

        api_oc = OccupationCodesApi(api_client=client)

        codes : List[OccupationCode] = api_oc.get_occupation_codes(**x_headers)
        for c in codes:
            print(pprint.pformat(object=json.loads(c.model_dump_json()), indent=1, width=200))

    def demoSubmitOccupationCode() -> None:
        from openapi_client.api.occupation_codes_api import OccupationCodesApi
        from openapi_client.api.events_api import EventsApi
        from openapi_client.exceptions import NotFoundException
        from openapi_client.models.submit_occupation_code import SubmitOccupationCode, OccupationDescription
        from openapi_client.models.language import Language
        from openapi_client.models.gender import Gender
        from openapi_client.models.event import Event
        from openapi_client.models.event_status import EventStatus
        from openapi_client.models.event_occupation_code_submitted import EventOccupationCodeSubmitted

        api_oc = OccupationCodesApi(api_client=client)
        api_ev = EventsApi(api_client=client)

        # submit new event
        desc = OccupationDescription(language=Language.DE, gender=Gender.MALE, value='Lebkuchenhausbauer') 
        
        code_uuid = str(uuid.uuid5(namespace=MY_UUID_NAMESPACE, name=desc.value)) # generate UUID from string

        code = SubmitOccupationCode(occupationCodeNr1=code_uuid, 
                                    occupationCodeNr2=code_uuid, 
                                    preferredLanguage=Language.DE, 
                                    descriptions=[desc])
        try:
            res = api_oc.submit_occupation_code(**x_headers, submit_occupation_code=code)
            print(pprint.pformat(object=json.loads(res.model_dump_json()), indent=1, width=200))
        except NotFoundException as nfe:
            body = json.loads(str(nfe.body))
            log.error('NotFoundException:%s', body['message'])
            return

        if res is None or res.event_id is None:
            raise Exception('no response')
        wait_event_id : str = res.event_id
        log.info('waiting for event:%s', wait_event_id)

        response : Optional[EventOccupationCodeSubmitted] = None
        while response is None:
            log.info('sleeping - waiting for my event')
            time.sleep(10)

            # check single event
            my_event : Event = api_ev.get_event(**x_headers, event_id=wait_event_id)
            log.info('my_event=%s', my_event)

            if my_event.status == EventStatus.PROCESSED and my_event.detail is not None and isinstance(my_event.detail.actual_instance,EventOccupationCodeSubmitted):
                log.info('event has been processed')
                response = my_event.detail.actual_instance

        api_ev.acknowledge_event(**x_headers, event_id=wait_event_id)

        log.info('response=%s', response.occupation)

    demo_commands = {
        'ListaOccupationCodes': demoListaOccupationCodes,
        'ListOperatingUnits': demoListOperatingUnits, # not implemented yet
        'ActivateSuvaCode': demoActivateSuvaCode,
        'InActivateCode': demoInActivateCode,
        'ClearAllEvents': demoClearAllEvents,
        'SubmitOccupationCode': demoSubmitOccupationCode,
    }

    parser = argparse.ArgumentParser(description='call demo')
    parser.add_argument('--debug', action='store_true', default=False, help='enable debug output')
    parser.add_argument('demo', choices=demo_commands.keys(), help='chose demo')
   
    args = parser.parse_args()

    if args.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    # setup token

    if config['Credentials'].getboolean('UseSignedJWT', False):
        api_config.access_token = getAccessTokenJWT()
    else:
        api_config.access_token = getAccessToken()

    if api_config.access_token is None:
        log.error('no access token')
        return

    log.info('AccessToken=%s...', api_config.access_token[0:5])
    client.default_headers['Authorization'] = 'Bearer ' + api_config.access_token  # see https://github.com/OpenAPITools/openapi-generator/issues/18041

    # call demo
    demo_func = demo_commands[args.demo]
    demo_func()

if __name__ == '__main__':
    main()
