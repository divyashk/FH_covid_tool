import requests
from datetime import date,datetime
import os
import smtplib
from time import time,ctime
import utility
import yaml
from flask import jsonify

def parse_pincode(result):
    output = []
    sessions = result['sessions']
    if len(sessions)==0:
        return output
    for session in sessions:
        if session['available_capacity'] >= 0:
            res = { 'name': session['name'], 'block_name':session['block_name'], \
            'age_limit':session['min_age_limit'], 'vaccine_type':session['vaccine'] , \
            'date':session['date'],'available_capacity':session['available_capacity'] }
            output.append(res)
    return output

def call_api(url, headers):
    response = requests.get(url, headers = headers)
    result_str = ""
    output = []
    if response.status_code == 200:
        result = response.json()
        # print(result)
        output = parse_pincode(result)
        if len(output) > 0:
            return jsonify(success=True, message = "Vaccine available" , output = output)
        else:
            return jsonify(success=True, message = 'Vaccine not available')
    else:
        return jsonify(success=False, message = 'Something went wrong')

def query(pincode): # Age --> 0 for 18 to 45 , 1 for 45+
    today = date.today()
    d1 = today.strftime("%d/%m/%Y")
    dt = str(d1).replace("/","-")
    url = "https://cdn-api.co-vin.in/api/v2/appointment/sessions/public/findByPin?pincode=" + pincode + "&date=" + dt
    headers = {'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/50.0.2661.102 Safari/537.36"}
    return call_api(url, headers)