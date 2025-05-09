from flask import Flask, render_template, request, redirect, url_for, flash, session
from authlib.integrations.flask_client import OAuth
from authlib.integrations.requests_client import OAuth2Session
from requests.auth import HTTPBasicAuth
from authlib.jose import jwt
import requests
import os
import secrets
import hashlib
import base64

app = Flask(__name__)
app.secret_key = 'your_secret_key'

#Ignore SSL (Not for Prod)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
os.environ['REQUESTS_CA_BUNDLE'] = ''  # Clear it if set

# disables SSL verification globally
class InsecureOAuth2Session(OAuth2Session):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.verify = False

# OAuth setup for PingFederate
oauth.register(
    name='ping',
    client_id='YOUR_CLIENT_ID',
    access_token_url='https://your-pf-server/as/token.oauth2',
    authorize_url='https://your-pf-server/as/authorization.oauth2',
    jwks_uri='https://your-pf-server/pf/JWKS',
    client_kwargs={
        'scope': 'openid profile email',
        'code_challenge_method': 'S256'
    },
    session_cls=InsecureOAuth2Session  # Disable SSL checks this is key
)

# Environment Config
QA_API_BASE = 'https://qa-ping.example.com:9999/pf-admin-api/v1'
PROD_API_BASE = 'https://prod-ping.example.com:9999/pf-admin-api/v1'
QA_USERNAME = 'qa_admin'
QA_PASSWORD = 'qa_password'
PROD_USERNAME = 'prod_admin'
PROD_PASSWORD = 'prod_password'
qa_auth = HTTPBasicAuth(QA_USERNAME, QA_PASSWORD)
prod_auth = HTTPBasicAuth(PROD_USERNAME, PROD_PASSWORD)

HEADERS = {
    'X-XSRF-Header': 'PingFederate',
    'Accept': 'application/json',
    'Content-Type': 'application/json'
}

# Simple in-memory migration log
migration_log = []

# ID mappings for PROD
ID_MAPPINGS = {
    'signing_keys': {
        'g0t7grow21iko1fhef8g8u810': 'PROD_SIGNING_KEY_ID',
    },
    'auth_contracts': {
        '8YMVZPucSVYlGkfX': 'PROD_AUTH_CONTRACT_ID',
    },
    'data_stores': {
        'LDAP-9A58A2D8A6FA41319A7FE261C8EADED0A035D17A': 'PROD_LDAP_AD',
    }
}

@app.before_request
def require_login():
    allowed_routes = ['login', 'callback', 'static']
    if request.endpoint in allowed_routes or request.path.startswith('/static/'):
        return
    if 'user' not in session:
        return redirect('/login')

@app.route('/login')
def login():
    session.permanent = True  # Extend session lifetime

    code_verifier = secrets.token_urlsafe(64)
    session['code_verifier'] = code_verifier
    print(f"[DEBUG] code_verifier stored: {code_verifier}")

    code_challenge = base64.urlsafe_b64encode(
        hashlib.sha256(code_verifier.encode()).digest()
    ).rstrip(b'=').decode('utf-8')

    redirect_uri = url_for('callback', _external=True)

    authorize_url = (
        "https://your-pf-server/as/authorization.oauth2"
        "?response_type=code"
        f"&client_id=YOUR_CLIENT_ID"
        f"&redirect_uri={redirect_uri}"
        f"&scope=openid profile email"
        f"&code_challenge={code_challenge}"
        f"&code_challenge_method=S256"
        f"&ad_groups=app_test1234"
    )

    print(f"[DEBUG] Redirecting to: {authorize_url}")
    return redirect(authorize_url)


@app.route('/callback')
def callback():
    code = request.args.get('code')
    code_verifier = session.get('code_verifier')
    redirect_uri = url_for('callback', _external=True)

    if not code:
        return "Error: Missing authorization code in callback URL.", 400
    if not code_verifier:
        return "Error: code_verifier not found in session. It may have expired, or cookies are blocked.", 400

    print(f"[DEBUG] code_verifier retrieved: {code_verifier}")

    # Proceed with token exchange as usual
    token_resp = requests.post(
        'https://your-pf-server/as/token.oauth2',
        data={
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': redirect_uri,
            'client_id': 'YOUR_CLIENT_ID',
            'code_verifier': code_verifier
        },
        verify=False
    )

    if token_resp.status_code != 200:
        return f"Token fetch failed: {token_resp.text}", 400

    token = token_resp.json()
    id_token = token.get('id_token')

    # Fetch JWKS and validate token
    jwks = requests.get('https://your-pf-server/pf/JWKS', verify=False).json()
    claims = jwt.decode(id_token, jwks)
    claims.validate()

    # Check group membership
    groups = claims.get('attr_memberof', [])
    if isinstance(groups, str):
        groups = [groups]

    if 'app_test1234' not in groups:
        return "Access Denied: You are not in the authorized AD group", 403

    # Store user session
    session['user'] = {
        'email': claims.get('email'),
        'name': claims.get('name'),
        'groups': groups
    }

    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

@app.route('/')
def index():
    response = requests.get(f'{QA_API_BASE}/idp/spConnections', auth=qa_auth, headers=HEADERS, verify=False)
    if response.status_code != 200:
        flash("Failed to fetch SP connections from QA.")
        return render_template('index.html', connections=[])
    connections = response.json().get('items', [])
    connections.sort(key=lambda x: x.get('name', '').lower())
    return render_template('index.html', connections=connections)

@app.route('/edit/<connection_id>')
def edit_connection(connection_id):
    response = requests.get(f'{QA_API_BASE}/idp/spConnections/{connection_id}', auth=qa_auth, headers=HEADERS, verify=False)
    if response.status_code != 200:
        flash("Failed to retrieve connection from QA.")
        return redirect(url_for('index'))

    connection = response.json()
    session['original_connection'] = connection

    endpoint_url = connection.get('spBrowserSso', {}).get('ssoServiceEndpoints', [{}])[0].get('url', '')
    base_url = connection.get('baseUrl', '')
    extended_properties = []

    for name, data in connection.get("extendedProperties", {}).items():
        for val in data.get("values", []):
            extended_properties.append({"name": name, "value": val})

    return render_template('edit_fields.html',
        connection_id=connection_id,
        name=connection['name'],
        entity_id=connection['entityId'],
        endpoint=endpoint_url,
        base_url=base_url,
        extended_properties=extended_properties
    )

@app.route('/submit', methods=['POST'])
def submit():
    connection = session.get('original_connection')
    if not connection:
        flash("Session expired or missing connection.")
        return redirect(url_for('index'))

    crq = request.form.get('crq')
    if not crq:
        flash("CRQ/INC is required to proceed with the migration.")
        return redirect(url_for('edit_connection', connection_id=request.form.get('connection_id')))

    connection['name'] = request.form['name']
    connection['entityId'] = request.form['entityId']
    connection['baseUrl'] = request.form['baseUrl']
    if connection.get('spBrowserSso', {}).get('ssoServiceEndpoints'):
        connection['spBrowserSso']['ssoServiceEndpoints'][0]['url'] = request.form['endpoint']

    # Extended properties
    connection['extendedProperties'] = {}
    for key in request.form:
        if key.startswith('ext_name_'):
            index = key.replace('ext_name_', '')
            value_key = f'ext_value_{index}'
            if value_key in request.form:
                name = request.form[key].strip()
                val = request.form[value_key].strip()
                if name:
                    connection['extendedProperties'][name] = {"values": [val]}

    connection = clean_connection_for_prod(connection)
    connection['id'] = ''

    response = requests.post(
        f'{PROD_API_BASE}/idp/spConnections',
        json=connection,
        auth=prod_auth,
        headers=HEADERS,
        verify=False
    )

    if response.status_code in (200, 201):
        migration_log.append({'name': connection['name'], 'crq': crq})
        flash("Successfully migrated connection to PROD.")
    else:
        flash(f"Migration failed: {response.text}")
    return redirect(url_for('index'))

@app.route('/log')
def log():
    return render_template('log.html', log=migration_log)

def clean_connection_for_prod(connection):
    def swap_id(field_id, mapping):
        return ID_MAPPINGS[mapping].get(field_id, field_id)

    signing = connection.get('credentials', {}).get('signingSettings', {})
    sid = signing.get('signingKeyPairRef', {}).get('id')
    if sid:
        signing['signingKeyPairRef']['id'] = swap_id(sid, 'signing_keys')

    mappings = connection.get('spBrowserSso', {}).get('authenticationPolicyContractAssertionMappings', [])
    for mapping in mappings:
        ref = mapping.get('authenticationPolicyContractRef', {})
        if ref.get('id'):
            ref['id'] = swap_id(ref['id'], 'auth_contracts')

        for source in mapping.get('attributeSources', []):
            ds_ref = source.get('dataStoreRef', {})
            if ds_ref.get('id'):
                ds_ref['id'] = swap_id(ds_ref['id'], 'data_stores')

        fulfillment = mapping.get('attributeContractFulfillment', {})
        for item in fulfillment.values():
            src = item.get('source', {})
            if src.get('type') == 'LDAP_DATA_STORE' and src.get('id'):
                src['id'] = swap_id(src['id'], 'data_stores')

    return connection

if __name__ == '__main__':
    app.run(debug=True)
