import firebase_admin
from firebase_admin import credentials
from firebase_admin import firestore
import pandas as pd
import os
import json

def dtol(data , n , ans):
    for i in range(1,n+1):
        i = str(i)
        try:
            ans.append(data[i])
        except:
            ans.append("")
    return ans

def register(filename , qid , uid):
    responses = pd.read_csv('./registrations/'+filename)
    cred = credentials.Certificate("creds.json")
    # firebase_admin.initialize_app(cred)

    db = firestore.client()
    for ind in responses.index:
        teamCode = responses['SecretCode'][ind]
        print(ind, teamCode)
        data = {
            'TeamName': responses['TeamName'][ind],
            'TeamLeader' : responses['TeamLeader'][ind],
            'answers': {'1': ''},
        }
        db.collection("users").document(uid).collection("quizzes").document(qid).collection('registered').document(teamCode).set(data, merge=True)
    
    os.remove('./registrations/'+filename)

def answerstocsv(qid , uid , questions):
    cred = credentials.Certificate("creds.json")
    db = firestore.client()
    docs = db.collection("users").document(uid).collection("quizzes").document(qid).collection('registered').stream()
    columns = ['code' , 'name']
    questions = int(questions)
    for i in range(1, questions+1):
        columns.append(i)
    final = []
    for doc in docs:
        docd = doc.to_dict()
        ans = [doc.id , docd['TeamName']]
        final.append(dtol(docd['answers'] , questions , ans))
    
    new = pd.DataFrame(final , columns=columns)
    new.to_csv('./answers/' + qid + '.csv') 
