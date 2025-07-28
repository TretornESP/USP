import jsonschema
import requests
import secrets
import json

class UspService:

    class Metadata:
        def __init__(self):
            pass

        @staticmethod
        def from_dict(dict):
            if not dict:
                raise Exception('Invalid metadata: None')
            metadata = UspService.Metadata()
            print(dict, flush=True)
            try:
                metadata.issuer = dict['issuer']
                metadata.authorization_endpoint = dict['authorization_endpoint']
                metadata.token_endpoint = dict['token_endpoint']
                metadata.jwks_uri = dict.get('jwks_uri', "")
                metadata.introspection_endpoint = dict.get('introspection_endpoint', "")
                metadata.userinfo_endpoint = dict.get('userinfo_endpoint', "")
                metadata.end_session_endpoint = dict.get('end_session_endpoint', "")
                metadata.scopes_supported = dict.get('scopes_supported', [])
            except KeyError as e:
                raise Exception('Invalid metadata: {}'.format(e))
            return metadata

        def to_dict(self):
            return {
                'issuer': self.issuer,
                'authorization_endpoint': self.authorization_endpoint,
                'token_endpoint': self.token_endpoint,
                'jwks_uri': self.jwks_uri,
                'introspection_endpoint': self.introspection_endpoint,
                'userinfo_endpoint': self.userinfo_endpoint,
                'end_session_endpoint': self.end_session_endpoint,
                'scopes_supported': self.scopes_supported
            }

    class AccessTokenResponse:
        def __init__(self):
            pass

        @staticmethod
        def from_dict(resdict):
            if not dict:
                raise Exception('Invalid access token response: None')
            response = UspService.AccessTokenResponse()
            print(resdict, flush=True)
            try:
                response.id_token = resdict['id_token']
                response.access_token = resdict['access_token']
                response.refresh_token = resdict.get('refresh_token', "")
                response.token_type = resdict.get('token_type', "")
                response.scope = resdict.get('scope', "")
            except KeyError as e:
                raise Exception('Invalid access token response: {}'.format(e))
            return response

        def to_dict(self):
            return {
                'id_token': self.id_token,
                'access_token': self.access_token,
                'refresh_token': self.refresh_token,
                'token_type': self.token_type,
                'scope': self.scope
            }

    CONFIG_SCHEMA = {
        "$id": "https://usp.coren.com/schema/config.json",
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "USP Configuration schema",
        "type": "object",
        "properties": {
            "$schema": {
                "type": "string",
                "description": "The schema for this file"
            },
            "sp_server": {
                "type": "string",
                "description": "The server that will be used for the service provider"
            },
            "callback": {
                "type": "string",
                "description": "The callback path for the service provider"
            },
            "auth_server": {
                "type": "string",
                "description": "The authentication server"
            },
            "client_id": {
                "type": "string",
                "description": "The client id for the service provider"
            },
            "client_secret": {
                "type": "string",
                "description": "The client secret for the service provider"
            },
            "scope": {
                "type": "string",
                "description": "The scope for the service provider"
            },
            "verify": {
                "type": "boolean",
                "description": "Verify the SSL certificate"
            }
        },
        "required": [
            "$schema",
            "sp_server",
            "callback",
            "auth_server",
            "client_id",
            "client_secret",
            "scope",
            "verify"
        ],
        "additionalProperties": False
    }    

    def __init__(self, sp_server, callback, auth_server, client_id, client_secret, scope, verify):
        self.sp_server = sp_server
        self.callback = callback
        self.auth_server = auth_server
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.verify = verify
        self.metadata = self.__get_auth_server_metadata()

    def __get_auth_server_metadata(self):
        metadata_url = '{}/.well-known/openid-configuration'.format(self.auth_server)
        r = requests.get(metadata_url, verify=self.verify)
        if r.status_code != 200:
            raise Exception('Failed to get auth server metadata')

        return UspService.Metadata.from_dict(r.json())
    
    def __get_callback_uri(self):
        return '{}{}'.format(self.sp_server, self.callback)

    def __get_unique_value(self):
        return secrets.token_hex(16)

    def get_auth_uri(self):
        return '{}?client_id={}&redirect_uri={}&scope={}&response_type=code&state={}'.format(
            self.metadata.authorization_endpoint,
            self.client_id,
            self.__get_callback_uri(),
            self.scope,
            self.__get_unique_value()
        )

    def get_logout_uri(self):
        return '{}?post_logout_redirect_uri={}/&client_id={}'.format(
            self.metadata.end_session_endpoint,
            self.sp_server,
            self.client_id
        )

    def get_claims(self, access_token):
        headers = {
            "Authorization": "Bearer {}".format(access_token)
        }
        r = requests.get(self.metadata.userinfo_endpoint, headers=headers, verify=self.verify)
        if r.status_code != 200:
            raise Exception('Failed to get user claims')
        return r.json()

    def getAccessToken(self, code):
        post_data = {
            "grant_type": "authorization_code",
            "code": code,
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "redirect_uri": self.__get_callback_uri()
        }
        r = requests.post(self.metadata.token_endpoint, data=post_data, verify=self.verify)
        if r.status_code != 200:
            raise Exception('Failed to get id token and access token')
        response = UspService.AccessTokenResponse.from_dict(r.json())
        # Check that the scopes are in the metadata
        if not set(response.scope.split()).issubset(set(self.metadata.scopes_supported)):
            raise Exception('Invalid scopes in access token response')
        return response

    @staticmethod
    def from_config_file(config_file):
        try:
            with open(config_file, 'r') as f:
                config = json.load(f)
        except Exception as e:
            raise Exception('Failed to load config file: {}'.format(e))

        try:
            if not config['$schema'] == UspService.CONFIG_SCHEMA['$id']:
                raise Exception('Invalid schema request')

            jsonschema.validate(config, UspService.CONFIG_SCHEMA)

            return UspService(
                config['sp_server'],
                config['callback'],
                config['auth_server'],
                config['client_id'],
                config['client_secret'],
                config['scope'],
                config['verify']
            )
        except KeyError as e:
            raise Exception('Invalid config file, missing keys: {}'.format(e))
        
        except jsonschema.exceptions.ValidationError as e:
            raise Exception('Schema validation failure: {}'.format(e))

    @staticmethod
    def from_config(config):
        try:
            jsonschema.validate(config, UspService.CONFIG_SCHEMA)

            return UspService(
                config['sp_server'],
                config['callback'],
                config['auth_server'],
                config['client_id'],
                config['client_secret'],
                config['scope'],
                config['verify']
            )

        except jsonschema.exceptions.ValidationError as e:
            raise Exception('Schema validation failure: {}'.format(e))

        except KeyError as e:
            raise Exception('Invalid config, missing keys: {}'.format(e))