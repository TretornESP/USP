from flask import Flask, request, redirect
from usp import UspService

service = None

def root():
    return '<a href="/login">Login</a>'

def login():
    authurl = service.get_auth_uri()
    return redirect(authurl, code=301)

def logged_in(data):
    return 'Logged in with data {} <br> <a href={}>logout</a>'.format(data, service.get_logout_uri())

def callback():
    code = request.args.get('code')
    return logged_in(service.getAccessToken(code).to_dict())

if __name__ == '__main__':
    service = UspService.from_config_file('.\conf\config.json')

    app = Flask(__name__)
    app.add_url_rule('/', 'root', root)
    app.add_url_rule('/login/', 'login', login)
    app.add_url_rule(service.callback, 'callback', callback)

    app.run(debug=True, host='0.0.0.0', port=8080)