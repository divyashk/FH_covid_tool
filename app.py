from flask import Flask, json, render_template, jsonify, request, session, flash, redirect, url_for, send_file
import utility
from werkzeug.utils import secure_filename
from functools import wraps
import os
import time
import math 
import datetime
import vaccine as v
import json
import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore

import threading
from passlib.hash import sha256_crypt
import re

"""
Init 
"""
cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred)
db = firestore.client()
app = Flask(__name__)
app.secret_key = 'some_secret'

"""
Functions
"""
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

def weight(i):
    return 5*max(1 , math.log2(i/3600))

"""
APIs
"""

@app.route('/register', methods=['POST'])
def register_user():
    '''
    Get the data from the request body in JSON Format
    @json needed
    - password
    - username
    - Rest any other details like name, etc
    '''
    print("Hello")
    data = request.json
    image = data['image']
    # print(image)
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


@app.route("/if_logged_in",methods=["POST"])
def if_logged_in():
    if 'logged_in' in session:
         return jsonify(success=True)
    else:
        return jsonify(success=False)

@app.route('/add_item_api', methods=['POST'])
@is_logged_in
def add_item_api():
    data = request.json
    username = session['username']
    data['username'] = session['username']
    data['votes'] = {}
    data['net_upvotes'] = 0
    data['quantity'] = int(data['quantity'])
    data['time'] = int(time.time())
    data['weight'] = 0
    compulsary_items = ["username",    "name", "contact",
                        "item", "quantity", "city", "state"]

    for field in compulsary_items:
        if field not in data:
            return jsonify(success=False, err_code='1', msg=field + ' not passed')

    # Adding the item into the database
    docref = None
    if "itemId" in data:
        docref = data["itemId"]
    doc_ref = db.collection("Inventory").document(data['item']).collection(data['state']).document(data['city']).collection("leads").document(docref)
    doc_ref.set(data , merge = True)

    if "itemId" not in data:

        # Also add some randome data to the docs
        db.collection("Inventory").document(data['item']).set( {"desc" : "Hello world" })
        db.collection("Inventory").document(data['item']).collection(data['state']).document(data['city']).set({"city_desc": "Wow"})

        db.collection("users").document(username).update({"leads" : firestore.ArrayUnion([doc_ref.path])})
        db.collection("references").document(doc_ref.id).set({"address" : doc_ref.path})
    doc = db.collection("states").document(data['state']).set({"cities" : firestore.ArrayUnion([data['city']])} , merge = True)
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
    cur_status = data['cur_status']
    net_upvotes = data['net_upvotes']
    address = db.collection("references").document(leadId).get().to_dict()["address"]
    address = address.split("/")
    doc = db.collection("Inventory").document(address[1]).collection(address[2]).document(address[3]).collection("leads").document(leadId).get().to_dict()
    ndata = {'votes' : {username : change_to} , 'net_upvotes' : net_upvotes + change_to - cur_status , 'weight' : doc["weight"] + (change_to - cur_status)*(weight(time.time() - doc["time"]))}
    db.collection("Inventory").document(address[1]).collection(address[2]).document(address[3]).collection("leads").document(leadId).set(ndata , merge=True)
    return jsonify(success=True)

@app.route('/delete_lead_api', methods=['POST'])
@is_logged_in
def delete_lead():
    data = request.json
    leadId = data['leadId']
    username = session['username']
    address = db.collection("references").document(leadId).get().to_dict()["address"]
    iaddress = address.split("/")
    db.collection("Inventory").document(iaddress[1]).collection(iaddress[2]).document(iaddress[3]).collection("leads").document(leadId).delete()
    db.collection("users").document(username).update({'leads' : firestore.ArrayRemove([address])})
    db.collection("references").document(leadId).delete()
    return jsonify(success=True)

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
            if "image" in userid_ref.to_dict():
                return jsonify(success=True , image=userid_ref.to_dict()["image"])
            else:
                return jsonify(success=True, image="")
        else:
            print("username doesn't exists")
            return jsonify(success=False, err_code='1')

    else:
        return jsonify(success=False, err_code='0')

@app.route('/add_comment', methods=['POST'])
@is_logged_in
def add_comment():
    data = request.json
    leadId = data['leadId']
    username = session['username']
    comment = data['comment']
    address = db.collection("references").document(leadId).get().to_dict()["address"]
    iaddress = address.split("/")
    db.collection("Inventory").document(iaddress[1]).collection(iaddress[2]).document(iaddress[3]).collection("leads").document(leadId).set({
        "comments" : firestore.ArrayUnion([{
            "comment" : comment , 
            "poster" : username , 
            "time" : datetime.datetime.now()
        }])
    } , merge = True)
    
    print("Hello")
    return jsonify(success=True)

@app.route('/get_states', methods=['POST'])
def get_states():
    """
    This nees the item and it finds all the subcollections
    """

    states = []
    collections = db.collection("Inventory").document(request.json["item"]).collections()

    for collection in collections:
        states.append(collection.id)

    return jsonify(success=True, states=states)


@app.route("/update_rating", methods=['POST'])
def update_rating():
    '''
    We need reviewer and reviewed in this
    Alsot he rating given by him
    '''
    data = request.json 
    ndata = db.collection("users").document(data["reviewed"]).get().to_dict()
    
    if "rating" in ndata:
        ln = len(ndata["rating"])
        cur = ndata["net_rating"]
        new_rating = ((cur*ln) + data["rating"]) / (ln + 1)
        if data["reviewer"] in ndata["rating"]:
            new_rating = (cur*ln + data["rating"] - ndata["rating"][data["reviewer"]]) / ln
    else:
        new_rating = data["rating"]

    db.collection("users").document(data["reviewed"]).set({
        "rating" : { data["reviewer"] : data["rating"] },
        "net_rating" : new_rating
    }, merge=True)

    return jsonify(success=True)

@app.route("/get_votes", methods=['POST'])
def get_votes():
    data = request.json 
    print("Get votes" , data)
    leadId = data["leadId"]
    ndata = db.collection("Inventory").document().get().to_dict()
    address = db.collection("references").document(leadId).get().to_dict()["address"]
    address = address.split("/")
    doc = db.collection("Inventory").document(address[1]).collection(address[2]).document(address[3]).collection("leads").document(leadId).get().to_dict()
    lisp = doc["votes"]
    upvoters = []
    downvoters = []
    for voter in lisp:
        dc = db.collection("users").document(voter).get().to_dict()
        rating = None
        if "net_rating" in dc:
            rating = dc["net_rating"]
        if lisp[voter] == 1:
            upvoters.append([voter,rating])
        elif lisp[voter] == -1:
            downvoters.append([voter, rating])
    print(upvoters)
    print(downvoters)
    return jsonify(upvoters = upvoters , downvoters = downvoters , urls = doc["imageReviews"])

@app.route("/imageReviewUpload", methods=['POST'])
def handle_image_upload():
    data = request.json 
    print("Image review upload" , data)
    leadId = data["leadId"]
    url = data["url"]
    address = db.collection("references").document(leadId).get().to_dict()["address"]
    address = address.split("/")
    doc = db.collection("Inventory").document(address[1]).collection(address[2]).document(address[3]).collection("leads").document(leadId).set({
        "imageReviews" : firestore.ArrayUnion([url])} , merge = True)
    return jsonify(success = True)

"""
Routes
"""
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

@app.route('/add', methods=['GET'])
@is_logged_in
def add():
    id = request.args.get('id');
    dict_pass = {};
    if id != None:
        dict_pass["id"] = id
        dict_pass["contact"] = request.args.get('contact');
        dict_pass["address"] = request.args.get('address');
        dict_pass["city"] = request.args.get('city');
        dict_pass["name"] = request.args.get('name');
        dict_pass["item_name"] = request.args.get('item');
        dict_pass["state"] = request.args.get('state');
        dict_pass["quantity"] = request.args.get('qty');

        for x in dict_pass.keys():
            if dict_pass[x] is None:
                print("missing value - ",x);

        return render_template("add.html", data=dict_pass, check = 1)
    else:
        return render_template("add.html", data=dict_pass, check = 0)


@app.route('/login', methods=['GET', 'POST'])
def login_register():
    '''
    The main login page which functions using the apis and all
    '''
    if "logged_in" in session and session["logged_in"]:
        return redirect(url_for("profile"))

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

@app.route('/profile')
@is_logged_in
def profile():
    if session['username']:
        username= session['username']
    return render_template("profile.html", username = username, isMe="yes", loginuser=username)

@app.route('/profile/<id>')
def profile_others(id):
    print("for id", id)

    username = ""
    if 'username' in session:
        username = session['username']

    return render_template("profile.html", username = id, isMe="no", loginuser=username)


@app.route('/logout')
def logout():
    session["logged_in"] = False
    session.clear()
    return redirect(url_for('find'))

@app.route('/vaccine' , methods=['GET' , 'POST'])
def vaccine():
    if request.method == "POST":
        return v.query(request.json["pincode"])
    return render_template("vaccine.html")

"""
Test routes
"""

@app.route('/testfind')
def testfind():
    return render_template('testfind.html')

@app.route('/testvote')
def testvote():
    return render_template('testvote.html')

@app.route('/testdelete')
def testdelete():
    return render_template('testdelete.html')

@app.route('/testcomment')
def testcomment():
    return render_template('testcomment.html')

"""
Main 
"""
if __name__ == '__main__':
    app.run(debug=True)
