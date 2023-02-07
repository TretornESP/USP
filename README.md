# Universal Service Provider (Native python OIDC library)

This library manages the authentication against an OIDC provider (for now only ADFS 19)

## Usage (python script)

```python
from usp import UspService

# Create a USP object
config = {
    "sp_server": "http://usp.YOURSITE.com:8080",
    "callback": "/login/oauth2/adfs",
    "auth_server": "srvadfs.YOURSITE.com",
    "client_id": "XXXXXXXX-XXX-XXX-XXXX-XXXXXXXXXXX",
    "client_secret": "XXXXXXXXXXXX_XXXXXXXXXX-XXXXXXXXXXXXXX",
    "scope": "openid allatclaims api_delete",
    "verify": False
}

# Load the service
usp = UspService.from_config(config)

# Get the authorization URL
auth_url = usp.get_authorization_url()

# Redirect the user to the authorization URL, depends on your framework
# redirect(auth_url, code=301)

# Get the token (depends on your framework, this is a callback)
#token = usp.getAccessToken(code)

# Get the logout URL
logout_url = usp.get_logout_url()

```

## Authentication

Once you are authenticated, the callback trigger will be called. 
You can get the user information from the session making use of the `code` field.

## Demo

You have a demo for a Flask application in the `flask-demo.py` file.

## Acknowledgements

This is basically a port from [Fabianlee's go implementation](https://fabianlee.org/2022/09/06/python-flask-oidc-protecting-client-app-and-resource-server-using-windows-2019-adfs/).
