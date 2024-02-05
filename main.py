import json
import uuid
import requests
from jose import jwt
from os import environ as env
from urllib.parse import quote_plus, urlencode
from urllib.request import urlopen

from authlib.integrations.flask_client import OAuth
from dotenv import find_dotenv, load_dotenv
from flask import Flask, request, redirect, render_template, session, url_for, jsonify, make_response
from google.cloud import datastore

USERS = "users"
BOATS = "boats"
LOADS = "loads"


ENV_FILE = find_dotenv()
if ENV_FILE:
    load_dotenv(ENV_FILE)

app = Flask(__name__)
app.secret_key = env.get("APP_SECRET_KEY")
# app.register_blueprint(loads.bp)

client = datastore.Client()
BOATS = "boats"

oauth = OAuth(app)
ALGORITHMS = ["RS256"]

CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

oauth = OAuth(app)
ALGORITHMS = ["RS256"]

CLIENT_ID = env.get("AUTH0_CLIENT_ID")
CLIENT_SECRET = env.get("AUTH0_CLIENT_SECRET")
DOMAIN = env.get("AUTH0_DOMAIN")

oauth.register(
    "auth0",
    client_id=env.get("AUTH0_CLIENT_ID"),
    client_secret=env.get("AUTH0_CLIENT_SECRET"),
    client_kwargs={
        "scope": "openid profile email",
    },
    server_metadata_url=f'https://{env.get("AUTH0_DOMAIN")}/.well-known/openid-configuration'
)

class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response

# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                            "description":
                                "Authorization header is missing"}, 401)
    
    jsonurl = urlopen("https://"+ DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://"+ DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                            "description":
                                "No RSA key in JWKS"}, 401)
    

# Controllers API
@app.route("/login")
def login():
    return oauth.auth0.authorize_redirect(
        redirect_uri=url_for("callback", _external=True)
    )

@app.route("/callback", methods=["GET", "POST"])
def callback():
    token = oauth.auth0.authorize_access_token()
    session["user"] = token

    
    user_name = session["user"]["userinfo"]["email"]
    boat_owner_id = session["user"]["userinfo"]["sub"]

    query = client.query(kind=USERS)
    query.add_filter("boat_owner_id", "=", boat_owner_id)
    result = list(query.fetch())


    if result == []:
        new_user = datastore.entity.Entity(key=client.key(USERS))
        new_user.update({"user_name": user_name, "boat_owner_id": boat_owner_id})
        client.put(new_user)

    return redirect("/")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(
        "https://" + env.get("AUTH0_DOMAIN")
        + "/v2/logout?"
        + urlencode(
            {
                "returnTo": url_for("index", _external=True),
                "client_id": env.get("AUTH0_CLIENT_ID"),
            },
            quote_via=quote_plus,
        )
    )

@app.route("/")
def index():
    jwt_content = session.get('user')
    pretty = json.dumps(session.get('user'), indent=4)
    id_token = None
    boat_owner_id = None

    if jwt_content:
        if "id_token" in jwt_content:
            id_token = jwt_content["id_token"]         
        
        if "userinfo" in jwt_content and "sub" in jwt_content["userinfo"]:
            boat_owner_id = jwt_content["userinfo"]["sub"]

    return render_template(
        "index.html",
        session=session.get("user"),
        pretty=pretty, boat_owner_id=boat_owner_id, id_token=id_token)
    

@app.route("/users", methods = ['GET'])
def get_users():
    if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res
    
    query = client.query(kind=USERS)
    results = list(query.fetch())

    for e in results:
        e["id"] = e.key.id
        e["self"] = request.host_url + "users/" + str(e["boat_owner_id"])
    
    return results, 200, {'Content-Type': 'application/json'}

# Create a boat if the Authorization header contains a valid JWT
@app.route('/boats', methods=['POST', 'GET', 'PUT', 'PATCH', 'DELETE'])
def boats_post():
    if request.method == 'POST':
        payload = verify_jwt(request)
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res        
        content = request.get_json()
        new_boat = datastore.entity.Entity(key=client.key(BOATS))
        # check if all required attributes were provided by client
        if not 'name' in content or not 'type' in content or not 'length' in content:
                res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
                res.mimetype = 'application/json'
                res.status_code = 400
                return res
        new_boat.update(
            {
                "name": content["name"], 
                "type": content["type"], 
                "length": content["length"], 
                "owner": payload["sub"],
                "loads": []
                })
        client.put(new_boat)
        new_boat["id"] = new_boat.key.id
        new_boat["self"] = request.base_url + '/' + str(new_boat["id"])
        res = make_response(json.dumps(new_boat))
        res.mimetype = 'application/json'
        res.headers.set('Location', new_boat['self'])
        res.status_code = 201
        return res
    elif request.method == "GET":
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res  
        query = client.query(kind=BOATS)
        payload = verify_jwt(request)
        query.add_filter("owner", "=", payload["sub"])
        count = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
            e["self"] = request.base_url + '/' + str(e['id'])
            for load in e['loads']:
                load['self'] = request.base_url + 'loads/' + str(load['id'])
        output = {"boats": results}
        if next_url:
            output['next'] = next_url
        output['count'] = count
        return output, 200, {'Content-Type': 'application/json'}
    # TODO comment out all delete function
    # Method to delete all boats
    # elif request.method == 'DELETE':
    #     query = client.query(kind=BOATS)
    #     results = list(query.fetch())
    #     for e in results:
    #         client.delete(e.key)
    #     return ('', 204)
    else:
        res = make_response(json.dumps({'Error':'Method Not Allowed'}))
        res.mimetype = 'application/json'
        res.headers.set('Allow', 'GET, POST')
        res.status_code = 405
        return res 
    
@app.route('/boats/<id>', methods=['GET', 'PUT', 'PATCH', 'DELETE', 'POST'])
def boats_put_delete(id):
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        key = client.key(BOATS, int(id))
        boat = client.get(key=key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res  
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        for e in boat['loads']:
            load_key = client.key(LOADS, int(e["id"]))
            load = client.get(key=load_key)
            load['carrier'] = None
            client.put(load)  
        client.delete(key)
        return ('', 204)
    elif request.method == 'GET':
        payload = verify_jwt(request)
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        boat_key = client.key(BOATS, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        boat["id"] = boat.key.id
        boat["self"] = request.base_url
        return json.dumps(boat)
    elif request.method == 'PUT':
        payload = verify_jwt(request)
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res
        content = request.get_json()
        boat_key = client.key(BOATS, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        # make sure all data attributes are provided by client
        if not 'name' in content or not 'type' in content or not 'length' in content:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res
        boat.update({"name": content["name"], "type": content["type"],
            "length": content["length"]})
        client.put(boat)
        boat["id"] = boat.key.id
        boat["self"] = request.base_url + "/boats/" + str(boat["id"])
        return '', 204, {'Content-Type': 'application/json'}
         
    elif request.method == 'PATCH':
        payload = verify_jwt(request)
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        content = request.get_json()
        boat_key = client.key(BOATS, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        if not 'name' in content and not 'type' in content and not 'length' in content:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res
        boat.update(content)
        client.put(boat)
        boat["id"] = id
        boat["self"] = request.url
        return '', 204, {'Content-Type': 'application/json'}
    else:
        res = make_response(json.dumps({'Error':'Method Not Allowed'}))
        res.mimetype = 'application/json'
        res.headers.set('Allow', 'GET, PUT, PATCH, DELETE')
        res.status_code = 405
        return res
    
@app.route('/loads', methods=['POST','GET', 'PUT','PATCH', 'DELETE'])
def loads_get_post():
    if request.method == 'POST':
        content = request.get_json()
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res
        new_load = datastore.entity.Entity(key=client.key(LOADS))
        new_load.update({
                        "volume": content["volume"], 
                        "carrier": None, 
                        "item": content["item"], 
                        "creation_date": content["creation_date"]})
        client.put(new_load)
        new_load["id"] = new_load.key.id
        new_load["self"] = request.url + "/" + str(new_load['id'])
        return new_load, 201, {'Content-Type': 'application/json'}
    elif request.method == 'GET':
        query = client.query(kind=LOADS)
        count = len(list(query.fetch()))
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        l_iterator = query.fetch(limit= q_limit, offset=q_offset)
        pages = l_iterator.pages
        results = list(next(pages))
        if l_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None
        for e in results:
            e["id"] = e.key.id
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        output['count'] = count
        return output, 200, {'Content-Type': 'application/json'}
    else:
        res = make_response(json.dumps({'Error':'Method Not Allowed'}))
        res.mimetype = 'application/json'
        res.headers.set('Allow', 'GET, POST')
        res.status_code = 405
        return res

@app.route('/loads/<id>', methods=['PUT', 'PATCH', 'DELETE', 'GET', 'POST'])
def loads_put_patch_delete(id):
    if request.method == 'GET':
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        key = client.key(LOADS, int(id))
        load = client.get(key)
        if load is None:
            res = make_response(json.dumps({"Error": "No boat with this load_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        load["id"] = load.key.id
        load["self"] = request.url
        if load["carrier"] is not None:
            load["carrier"]["self"] = request.host_url + "boats/" + str(load["carrier"]["id"])
        return load, 200, {'Content-Type': 'application/json'}
    elif request.method == 'PUT':
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        content = request.get_json()
        if "volume" not in content or "item" not in content or "creation_date" not in content:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res  
        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)

        if load is None:
            res = make_response(json.dumps({"Error": "No boat with this load_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
        load.update({"volume": content["volume"], "item": content["item"], 
                         "creation_date": content["creation_date"]})
        client.put(load)
        load["id"] = id
        load["self"] = request.host_url + "loads/" + str(id)
        return '', 204, {'Content-Type': 'application/json'}
    elif request.method == 'PATCH':
        if 'application/json' not in request.accept_mimetypes:
            res = make_response(json.dumps({"Error": "Not Acceptable"}))
            res.mimetype = 'application/json'
            res.status_code = 406
            return res 
        content = request.get_json()
        if "volume" not in content and "item" not in content and "creation_date" not in content:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required attributes"}))
            res.mimetype = 'application/json'
            res.status_code = 400
            return res  
        load_key = client.key(LOADS, int(id))
        load = client.get(key=load_key)
        if load is None:
            res = make_response(json.dumps({"Error": "No boat with this load_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
        load.update(content)
        client.put(load)
        load["id"] = id
        load["self"] = request.host_url + "loads/" + str(id)
        return '', 204, {'Content-Type': 'application/json'}
    elif request.method == 'DELETE':
        key = client.key(LOADS, int(id))
        load = client.get(key=key)
        if load is None:
            res = make_response(json.dumps({"Error": "No boat with this load_id exists"}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        
        if load["carrier"] is not None:
            boat_id = load["carrier"]["id"]
            boat_key = client.key(BOATS, int(boat_id))
            boat = client.get(key=boat_key)
            load_index = None            
            for load in range(len(boat["loads"])):
                if boat["loads"][load]["id"] == id:
                    load_index = load
            if load_index is not None:
                boat["loads"].pop(load_index)
                client.put(boat)

        client.delete(key)
        return ('',204)
    else:
        res = make_response(json.dumps({'Error':'Method Not Allowed'}))
        res.mimetype = 'application/json'
        res.headers.set('Allow', 'PUT, PATCH, DELETE, GET')
        res.status_code = 405
        return res
    
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT','DELETE'])
def add_delete_load(boat_id, load_id):
    
    if request.method == 'PUT':
        payload = verify_jwt(request)
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        if boat is None or load is None:
            res = make_response(json.dumps({"Error": "No resource with either load_id or boat_id exists."}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        if load["carrier"] is not None:
            res = make_response(json.dumps({"Error": "This boat is already loaded on another boat"}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        boat['loads'].append({"id": load.id, "self": request.host_url +  '/loads/' + str(load.id)})
        client.put(boat)
        load['carrier'] = {"id": boat.id, "self": request.host_url +  '/boats/' + str(boat.id)}
        client.put(load)
        return '', 204, {'Content-Type': 'application/json'}
    if request.method == 'DELETE':
        payload = verify_jwt(request)
        boat_key = client.key(BOATS, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(LOADS, int(load_id))
        load = client.get(key=load_key)
        if boat is None or load is None:
            res = make_response(json.dumps({"Error": "No resource with either load_id or boat_id exists."}))
            res.mimetype = 'application/json'
            res.status_code = 404
            return res
        if boat["owner"] != payload["sub"]:
            res = make_response(json.dumps({"Error": "Boat owned by another user. You are not permitted to access this resource."}))
            res.mimetype = 'application/json'
            res.status_code = 403
            return res
        for i, e in enumerate(boat['loads']):
            if load.id == e.get("id"):
                boat['loads'].pop(i)
                load['carrier'] = None
                client.put(boat)
                client.put(load)
                return ('', 204)
        res = make_response(json.dumps({"Error": "No resource with either load_id or boat_id exists."}))
        res.mimetype = 'application/json'
        res.status_code = 404
        return res
    else:
        res = make_response(json.dumps({'Error':'Method Not Allowed'}))
        res.mimetype = 'application/json'
        res.headers.set('Allow', 'PUT, DELETE')
        res.status_code = 405
        return res

  
if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)

