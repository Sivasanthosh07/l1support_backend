from flask import Flask, request
from flask_cors import CORS
from model import ask_logs
from okta_helper import (
  get_okta_user_by_login, 
  reset_okta_user_passwd_via_email, 
  get_okta_users_factors_by_login,
  reset_okta_user_mfa_factor_by_id,
  is_admin, 
  is_app_owner,
  revoke_okta_user_token,
  get_okta_user_token,
  get_okta_userinfo,
  calculate_adaptive_risk,
  okta_user_mfa_push_factor_verify
)
from constants import UserRiskPercentage
from decorators import validate_access_token

app = Flask(__name__)
CORS(app)


@app.get('/api/users/<username>')
@validate_access_token
def get_user(username: str):
  '''
  Fetch Okta user information by provided username.
  '''
  # Fetch user using Okta admin API
  userinfo, status_code = get_okta_user_by_login(username)
  if  status_code != 200:
    return {
      'status': 'failed',
      'message': 'Something went wrong, failed to fetch user details'
    }, status_code
  profile: dict = userinfo.get('profile')
  
  # Check if user has any adptive risk and set risk % accordingly
  adaptive_risk, status = calculate_adaptive_risk(userinfo.get('id'))

  # Check if user if admin or app-owner and set risk % accordingly
  risk_percentage = UserRiskPercentage.DEFAULT.value
  risk_reason = "Low risk user"
  if adaptive_risk != None:
    risk_reason = adaptive_risk.get('reasons')
    if adaptive_risk.get('level') == 'HIGH':
      risk_percentage = UserRiskPercentage.APP_OWNER.value      
    elif adaptive_risk.get('level') == 'MEDIUM':
      risk_percentage = UserRiskPercentage.APP_OWNER.value
  elif is_admin(userinfo.get('id')):
    risk_percentage = UserRiskPercentage.ADMIN.value
    risk_reason = 'Privileged user'
  elif is_app_owner(username):
    risk_percentage = UserRiskPercentage.APP_OWNER.value
    risk_reason = 'Privileged user'

  return {
    'status': 'success',
    "username": profile.get('login'),
    "user_id": userinfo.get('id'),
    "last_login": userinfo.get('lastLogin'),
    "last_password_changed": userinfo.get('passwordChanged'),
    "risk_percentage": risk_percentage,
    "risk_reason": risk_reason
  }


@app.post('/api/users/<username>/change-password')
@validate_access_token
def change_user_password(username: str):
  '''
  Send email to user for restting their password.
  '''
  # Fetch user using Okta admin API for userid
  userinfo, status_code = get_okta_user_by_login(username)
  if  status_code != 200:
    return {
      'status': 'failed',
      'message': 'User not found.'
    }, 404  
  # Send rest password mail to user using Okta User Lfecycle API
  status = reset_okta_user_passwd_via_email(userinfo.get('id'))
  if status == 200:
    return {
      'status': 'success',
      'message': "Reset password link sent on user's email successfully." 
    }
  return {
    'status': 'failed',
    'message': "Failed to send reset password link on user's email." 
  }, status


@app.get('/api/users/<username>/mfa-factors')
@validate_access_token
def get_user_enrolled_factors(username: str):
  factors, status_code = get_okta_users_factors_by_login(username)
  if status_code != 200:
    return {
      'status': 'failed',
      'message': 'Failed to fetch factors for user.',
    }, 500    
  result = list(map(lambda f: {
            'factor_id': f.get('id'),
            'factor_type': f.get('factorType'),
            'provider': f.get('provider'),
            'status': f.get('status')
          }, factors))
  return {
    'status': 'success',
    'factors': result

  }  

@app.delete('/api/users/<username>/mfa-factors/<factorid>')
@validate_access_token
def reset_user_mfa(username: str, factorid: str):
  status = reset_okta_user_mfa_factor_by_id(username, factorid)
  # print(status)
  if status == 204:
    return {
      'status': 'success',
      'message': "Successfully reset user's MFA factor for provided id." 
    }
  return {
      'status': 'failed',
      'message': "Failed to reset user's MFA factor for provided id." 
    }


@app.post('/api/tokens/revoke')
def revoke_user_token():
  req_body = request.json
  access_token = req_body.get('access_token')
  status = revoke_okta_user_token(access_token)
  if status == 200:
    return {
        'status': 'success',
        'message': "Successfully revoked user's access token."
    }, 200
  return {
      'status': 'failed',
      'message': "Failed to revoke user's access token"
  }, 500

@app.post('/api/tokens')
def get_user_token():
  req_body = request.json
  auth_code = req_body.get('Code')
  # print(auth_code)
  res, status_code = get_okta_user_token(auth_code)
  # print('tokens :: ', res)
  access_token: dict = res.get('access_token')
  # print('access_token : ', access_token)
  if status_code == 200:
    return {
        'status': 'success',
        'message': "Successfully get user's access token.",
        'token_type': res.get('token_type'),
        'access_token': access_token,
        'id_token': res.get('id_token')
    }, 200
  return {
      'status': 'failed',
      'message': "Failed to get user's access token"
  }, 500

@app.get('/api/v1/users/<username>/factors/<factorid>/transactions')
def mfa_push_factor_verify(username: str, factorid: str):
  output = okta_user_mfa_push_factor_verify(username, factorid)
  status = output["status"]
  factorResult = output["factorResult"]

  if status == 200:
    if factorResult == 'SUCCESS':
      return {
        'status': 'success',
        'message': "Successfully verified push MFA factor.",
        'factorResult': factorResult 
      }
    else:
      return {
        'status': 'failed',
        'message': "Failed to verify push MFA factor.",
        'factorResult': factorResult
      }
  return {
      'status': 'failed',
      'message': "Failed to verify a push MFA factor.",
      'factorResult': factorResult
    }

@app.route('/ask_logs/',methods=['POST'])
def ask_logss():
  req_body=request.json
  # print(req_body)
  username=request.args.get("username")
  # print(username)
  question=req_body.get('question')
  ans=ask_logs(username,question)
  # print(ans)
  return {
    'status':'Success',
    'result': ans
  },200

@app.get('/api/userinfo')
@validate_access_token
def get_Current_user_info():
  '''
  Fetch Okta user information by provided username.
  '''
  # Fetch user using Okta admin API
  userinfo, status_code = get_okta_userinfo()
  if  status_code != 200:
    return {
      'status': 'failed',
      'message': 'Something went wrong, failed to fetch user details'
    }, status_code
  profile: dict = userinfo.get('profile')

  print(userinfo)

  if is_admin(userinfo.get('id')):
    return {
      'role': 'ADMIN',
      "username": profile.get('firstName') + ' ' + profile.get('lastName'),
      "user_id": userinfo.get('id'),
      "email": profile.get('login'),
    }
  else:
    return {
      'role': 'USER',
      "username": profile.get('firstName') + ' ' + profile.get('lastName'),
      "user_id": userinfo.get('id'),
      "email": profile.get('login'),
    }


  