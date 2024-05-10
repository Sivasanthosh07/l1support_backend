import requests
from flask import request
from os import environ
import base64
import pandas as pd
import time
import json
from constants import OKTA_ADMIN_GROUP_ID, OKTA_APP_GROUP_ID, USER_TOKEN_TYPE_HINT
OKTA_API_TOKEN = environ.get('OKTA_API_TOKEN')
OKTA_DOMAIN_URL = environ.get('OKTA_DOMAIN_URL')
OKTA_HELPDESK_CLIENT_ID = environ.get('OKTA_HELPDESK_CLIENT_ID')
OKTA_HELPDESK_CLIENT_SECRET = environ.get('OKTA_HELPDESK_CLIENT_SECRET')
import logging

def get_okta_user_by_login(username: str) -> (dict, int):
  '''
  Retreive user details using Okta Users API for provided username.
  :param username: Okta user login field.
  '''
  res =  requests.get(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{username}",
    headers={
        "Authorization": request.headers.get('Authorization')
    }
  )
  if res.status_code == 200:
    return res.json(), res.status_code
  else:
    return None, res.status_code

def reset_okta_user_passwd_via_email(userid: str) -> int:
  '''
  Send rest password link on user's email using Okta User APIs
  :param userid: User's ID 
  '''
  res =  requests.post(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/lifecycle/reset_password",
    params={
      'sendEmail': True
    },
    headers={
        "Authorization": request.headers.get('Authorization')
    }
  )
  try:
    res_body = res.json()
    logging.warn(res_body.get('errorSummary'))  
  except Exception as e:
    logging.warning(e)  
  return res.status_code


def reset_okta_user_mfa_factors(userid: str) -> int:
  '''
  Reset user's mfa factors using Okta User APIs
  :param userid: User's ID 
  '''
  res =  requests.post(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/lifecycle/reset_factors",
    headers={
        "Authorization": request.headers.get('Authorization')
    }
  )
  try:
    res_body = res.json()
    logging.warn(res_body.get('errorSummary'))  
  except Exception as e:
    logging.warning(e)  
  return res.status_code

def get_okta_users_factors_by_login(username: str) -> (list[dict], int):
  '''
  List enrolled factors by user.
  :param username: Okta User's login field
  '''
  userinfo, _status_code = get_okta_user_by_login(username)
  userid = userinfo.get('id')
  res =  requests.get(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/factors",
    headers={
        "Authorization": request.headers.get('Authorization')
    }
  )
  if res.status_code == 200:
    return res.json(), res.status_code
  else:
    return None, res.status_code

def reset_okta_user_mfa_factor_by_id(username: str, factorid: str) -> int:
  '''
  Reset user's mfa factor by id.
  :param username: Okta User's login field
  :param factorid: Factor ID 
  '''
  userinfo, _status_code = get_okta_user_by_login(username)
  userid = userinfo.get('id')
  res =  requests.delete(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/factors/{factorid}",
    headers={
        "Authorization": request.headers.get('Authorization')
    }
  )
  return res.status_code

def reset_okta_user_mfa_push_factor_challenge(username: str, factorid: str) -> int:
  userinfo, _status_code = get_okta_user_by_login(username)
  userid = userinfo.get('id')

  res =  requests.post(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/factors/{factorid}/verify",
    headers={
      'Authorization': f"SSWS {OKTA_API_TOKEN}"
        # "Authorization": request.headers.get('Authorization')
    }
  )
  transactionid = res.json()["_links"]["poll"]["href"].split("/")[-1]

  return {"status":res.status_code,
          "transactionid":transactionid}

def okta_user_mfa_push_factor_verify(username: str, factorid: str) -> int:
  userinfo, _status_code = get_okta_user_by_login(username)
  userid = userinfo.get('id')
  transactionid = reset_okta_user_mfa_push_factor_challenge(username, factorid)["transactionid"]

  for i in range(60):
    time.sleep(1)
    res =  requests.get(
      f"https://{OKTA_DOMAIN_URL}/api/v1/users/{userid}/factors/{factorid}/transactions/{transactionid}",
      headers={
        'Authorization': f"SSWS {OKTA_API_TOKEN}"          
      }
    )
    factorResult = res.json()["factorResult"]   
    if (factorResult == "SUCCESS") or (factorResult == 'REJECTED'):
      break
    else:
      factorResult = "TIMEOUT"

  return {
    "status":res.status_code,
    "factorResult":factorResult
    }

def is_admin(user_id: str) -> bool:

  res =  requests.get(
  f"https://{OKTA_DOMAIN_URL}/api/v1/users/{user_id}/roles",
  headers={
      'Authorization': f"SSWS {OKTA_API_TOKEN}"
      # "Authorization": request.headers.get('Authorization')
  }
  )

  if res.status_code == 200:
    if len(res.json()):
      return True
    else:
      return False
  else:
    logging.warning(f"is_admin():: Response status: {res.status_code}")
    return False

def calculate_adaptive_risk(user_id: str) -> (dict, int):

  res = requests.get(
  f'https://{OKTA_DOMAIN_URL}/api/v1/logs?filter=debugContext.debugData.risk co "level=HIGH" and actor.id eq "{user_id}"',
  headers={
      "Authorization": request.headers.get('Authorization')
  }
  )

  if res.status_code == 200 and len(res.json()) == 0:
    res = requests.get(
    f'https://{OKTA_DOMAIN_URL}/api/v1/logs?filter=debugContext.debugData.risk co "level=MEDIUM" and actor.id eq "{user_id}"',
    headers={
        "Authorization": request.headers.get('Authorization')
    }
    )
  
  if res.status_code == 200 and len(res.json()):
    adaptive_risk = get_adaptive_risk(res.json().pop())
    if adaptive_risk.get('level') == 'HIGH' or adaptive_risk.get('level') == 'MEDIUM':
      return adaptive_risk, res.status_code
    else:
      return None, res.status_code
  else:
    logging.warning(f"adaptive_risk():: Response status: {res.status_code}")
    return None, res.status_code

   
def is_app_owner(username: str) -> bool:
  # Fetch app group members
  res =  requests.get(
    f"https://{OKTA_DOMAIN_URL}/api/v1/groups/{OKTA_APP_GROUP_ID}/users",
    headers={
        # 'Authorization': f"SSWS {OKTA_API_TOKEN}"
        "Authorization": request.headers.get('Authorization')
    }
  )
  if res.status_code == 200:
    group_members: list[dict] = res.json()
    for member in group_members:
      member_profile = member.get('profile')
      if member_profile.get('login') == username:
        return True
    return False
  else:
    logging.warning(f"is_app_owner():: Response status: {res.status_code}")
    return False  

def revoke_okta_user_token(access_token: str):
  client_creds = base64.b64encode(
      f"{OKTA_HELPDESK_CLIENT_ID}:{OKTA_HELPDESK_CLIENT_SECRET}".encode('ascii')).decode("ascii")
  res = requests.post(
      f"https://{OKTA_DOMAIN_URL}/oauth2/v1/revoke",
      headers={
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': f"Basic {client_creds}"
      },
      data={
          'token': access_token,
          'token_type_hint': USER_TOKEN_TYPE_HINT
      }
  )
  return res.status_code

def get_okta_user_token(auth_code: str):
  client_creds = base64.b64encode(
      f"{OKTA_HELPDESK_CLIENT_ID}:{OKTA_HELPDESK_CLIENT_SECRET}".encode('ascii')).decode("ascii")

  res = requests.post(
      f"https://{OKTA_DOMAIN_URL}/oauth2/v1/token",
      headers={
          'Accept': 'application/json',
          'Content-Type': 'application/x-www-form-urlencoded',
          'Authorization': f"Basic {client_creds}"
      },
      data={
          'grant_type':'authorization_code',
          'code': {auth_code},
          'redirect_uri': f'http://localhost:3000/callback'
      }
  )

  return res.json(), res.status_code

def get_okta_userinfo() -> (list[dict], int):
  res =  requests.get(
    f"https://{OKTA_DOMAIN_URL}/api/v1/users/me",
    headers={
        "Authorization": request.headers.get('Authorization')
     
    }
  )
  # print(res)
  return res.json(), res.status_code

def get_okta_logs(user_id:str):
  url = "https://"+OKTA_DOMAIN_URL+"/api/v1/logs?q="+user_id+"?"
  payload = {}
  headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'SSWS '+OKTA_API_TOKEN+''
  }
  response = requests.request("GET", url, headers=headers, data=payload)
  data=json.loads(response.text)
  df = pd.json_normalize(data)
  df = df[df['actor.alternateId'] == user_id]
  df=df.tail(30)
  nan_count = df.isna().sum()
  none_count = df.isin([None]).sum()
  total_nan_none_count = nan_count + none_count
  # Drop columns where the total count of NaN or None values exceeds 26
  columns_to_drop = total_nan_none_count[total_nan_none_count > 26].index
  df.drop(columns=columns_to_drop,inplace=True)
  return df

def get_adaptive_risk(logs: dict) -> dict:
  debugContext: dict = logs.get('debugContext')
  debugData: dict = debugContext.get('debugData')
  risk: dict = debugData.get('risk')
  adaptive_risk: dict = string_to_dict(risk)
  return adaptive_risk

def string_to_dict(input_string):
  input_string = input_string.strip('{}')
  pairs = input_string.split(',')
  result = {}
  for pair in pairs:
      key, value = pair.split('=')
      key = key.strip()
      value = value.strip()
      result[key] = value

  return result