from flask import Flask, json, render_template, jsonify, request, session, flash, redirect, url_for, send_file
import utility
from werkzeug.utils import secure_filename
from functools import wraps
import os

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

import threading
from passlib.hash import sha256_crypt
import re

cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)

app.secret_key = 'some_secret'

def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login_register'))
    return wrap


def is_user_id_valid(uid):
    # Return True or False depending on if the username is valid or not
    # Does NOT check if the username already exists or not

    regex = re.compile('[@_!#$%^&*()<>?/\|}{~:]')
    if (regex.search(uid) != None):
        return False

    return True


@app.route('/add_item_api', methods=['POST'])
@is_logged_in
def add_item_api():
    data = request.json
    username = session['username']
    data['username'] = session['username']
    data['votes'] = {}
    data['net_upvotes'] = 0
    data['quantity'] = int(data['quantity'])
    compulsary_items = ["username",    "name", "contact",
                        "item", "quantity", "city", "state"]

    for field in compulsary_items:
        if field not in data:
            return jsonify(success=False, err_code='1', msg=field + ' not passed')

    # Adding the item into the database
    doc_ref = db.collection("Inventory").document(data['item']).collection(
        data['state']).document(data['city']).collection("leads").document()
    doc_ref.set(data)

    db.collection("users").document(username).update({"leads" : firestore.ArrayUnion([doc_ref.path])})

    # Also updating the list of available cities in a state
    doc = db.collection("states").document(data['state']).get()
    if doc.exists:
        fields = doc.to_dict()
        # only if the city is not added to the set of cities for this state
        if data['city'] not in fields['cities']:
            fields['cities'].append(data['city'])
            db.collection("states").document(data['state']).set(fields)
    else:
        # creating the new doc for the state
        dict = {"cities": [data["city"]]}
        db.collection("states").document(data['state']).set(dict)

    return jsonify(success=True)

@app.route('/get_leads_api', methods=['POST'])
def get_leads_api():
    data = request.json
    state = data['state']
    city = data['city']    
    item = data['item']

    docs = db.collection("Inventory").document(item).collection(state).document(city).collection("leads").stream()
    lisp = []
    for doc in docs:
        tdoc = doc.to_dict()
        tdoc['leadId'] = doc.id
        lisp.append(tdoc)
    lisp = sorted(lisp , key = lambda i : (-i['net_upvotes'] , -i['quantity']))
    if "username" in session:
        username = session['username']
        for dt in lisp:
            dt['status'] = 0
            if username in dt['votes']:
                dt['status'] = dt['votes'][username]
    # data = {"data" : lisp}
    
    return jsonify(success=True , data=lisp)
        # return jsonify(success=False, err_code='0')

@app.route('/vote_api', methods=['POST'])
@is_logged_in
def vote():
    data = request.json
    change_to = data['change_to']
    username = session['username']
    leadId = data['leadId']
    item = data['item']
    city = data['city']
    state = data['state']
    cur_status = data['cur_status']
    net_upvotes = data['net_upvotes']

    ndata = {'votes' : {username : change_to} , 'net_upvotes' : net_upvotes + change_to - cur_status}
    db.collection("Inventory").document(item).collection(state).document(city).collection("leads").document(leadId).set(ndata , merge=True)
    return jsonify(success=True)

@app.route('/favicon.ico')
def give_favicon():
    return send_file('static/download.png')

@app.route('/')
@app.route('/find')
def find():
    username = ""

    if ("username" in session):
        username = session["username"]

    return render_template('find.html', username=username)

@app.route('/testfind')
def testfind():
    return render_template('testfind.html')

@app.route('/testvote')
def testvote():
    return render_template('testvote.html')

@app.route('/add')
@is_logged_in
def add():
    return render_template('add.html')

@app.route('/user_info', methods=['GET', 'POST'])
@is_logged_in
def user_info():
    user_info = db.collection(u'users').document(session['username']).get()

    if user_info.exists:
        print("User exists")
        resDict = {
            "name": user_info.get('name'),
            "contact": user_info.get('phone'),
        }
        return jsonify(success=True, user_info=resDict)
    else:
        print("User doesn't exists")
        return jsonify(success=False, err_code='1')


@app.route('/login', methods=['GET', 'POST'])
def login_register():
    '''
    The main login page which functions using the apis and all
    '''

    if "logged_in" in session and session["logged_in"]:
        return redirect(url_for("add"))

    if request.method == 'GET':
        return render_template('login.html')
    else:
        data = request.json
        pass_hash = db.collection("users").document(
            data["username"]).get().to_dict()['password']
        if sha256_crypt.verify(data["password"], pass_hash):

            if data["username"] == "root":
                # This is a superuser!!
                session['is_super_user'] = True
                session['super_user_secret'] = "admin@ppd"

            session['logged_in'] = True
            session['username'] = data['username']
            return jsonify(success=True)
        else:
            return jsonify(success=False)

@app.route('/logout')
def logout():
    session["logged_in"] = False
    session.clear()
    return redirect(url_for('login_register'))


@app.route('/register', methods=['POST'])
def register_user():
    '''
    Get the data from the request body in JSON Format
    @json needed
    - password
    - username
    - Rest any other details like name, etc
    '''

    data = request.json

    compulsary_items = ["username", "password"]

    for item in compulsary_items:
        if item not in data:
            return jsonify(success=False, err_code='1', msg=item + 'not passed')

    if (is_user_id_valid(data['username'])):
        # User id is valid, go ahead
        data['password'] = sha256_crypt.encrypt(str(data['password']))

        # Update the user in the database
        db.collection("users").document(data['username']).set(data, merge=True)

        session['logged_in'] = True
        session['username'] = data['username']
        return jsonify(success=True)
    else:
        return jsonify(success=False, err_code='0')


@app.route('/username_exists', methods=['POST'])
def check_if_username_exists():
    # needs username and check if the username exists or not
    # returns true and false depending on if it exists

    req_data = request.json

    if is_user_id_valid(req_data["username"]):
        # Make the request now
        userid_ref = db.collection(u'users').document(
            req_data['username']).get()

        if userid_ref.exists:
            print("username exists")
            return jsonify(success=True)
        else:
            print("username doesn't exists")
            return jsonify(success=False, err_code='1')

    else:
        return jsonify(success=False, err_code='0')


if __name__ == '__main__':
    app.run(debug=True)
