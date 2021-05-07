from flask import Flask, json, render_template, jsonify, request, session, flash, redirect, url_for, send_file
import utility
from werkzeug.utils import secure_filename
from functools import wraps
import os

import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import threading
import re



cred = credentials.Certificate('creds.json')
firebase_admin.initialize_app(cred)
db = firestore.client()

app = Flask(__name__)

app.secret_key = 'some_secret'



@app.route('/favicon.ico')
def give_favicon():
    return send_file('static/quiz.svg')


@app.route('/')
def index():
    divyash = db.collection("users").where("name","==","Divyasheel");
    name = divyash
    return render_template('index.html', name=name)



if __name__ == '__main__':
    app.run(debug=True)
