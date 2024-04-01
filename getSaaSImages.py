import time
import requests
import hashlib
import json
import hmac
from dotenv import load_dotenv
import os

load_dotenv()

API_KEY = os.getenv("API_KEY")
API_SECRET=os.getenv("API_SECRET")

def get_images(registry,token):
    endpoint = "https://e11d515bfb.cloud.aquasec.com/api/v2/images?order_by=created&registry="+registry
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json",
        "Authorization": "Bearer " + token
    }
    
    response = requests.get(endpoint, headers=headers)
    data = response.json()
    field_list = data['result']
    for fields in field_list:
        print(fields['name'])
        print(fields['created'])
        print(fields['image_build_date'])
        
def get_token():
    endpoint='https://api.cloudsploit.com'
    path='/v2/tokens'
    url=endpoint + path
    timestamp=str(int(time.time() * 1000))
    method='POST'
    json_data = {
                "allowed_endpoints": [
                    "DELETE",
                    "GET",
                    "HEAD",
                    "OPTIONS",
                    "PATCH",
                    "POST",
                    "PUT",
                    "ANY"
                ],
                "validity": 240,
                "csp_roles":["jasonRole"]
            }

    body=json.dumps(json_data,separators=(',', ':'))

    string = timestamp + method + path + body

    sig = hmac.new(API_SECRET.encode('utf-8'), msg=string.encode('utf-8'), digestmod=hashlib.sha256).hexdigest()

    headers={
            "Accept": "application/json",
            "Content-Type": "application/json",
            "X-API-Key": API_KEY,
            "X-Signature": sig,
            'X-Timestamp': timestamp}
    r = requests.post(url,data=body,headers=headers)
    data = r.json()
    #print(data)
    return data['data']

token = get_token()
get_images('Docker Hub',token)
