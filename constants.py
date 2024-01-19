from enum import Enum

OKTA_ADMIN_GROUP_ID = "00gcq0tey0vGpNBlo5d7"  # Admin Group
OKTA_APP_GROUP_ID = "00gdgzj4fdUlE5umE5d7"  # App Owners Group
USER_TOKEN_TYPE_HINT = "access_token"

class UserRiskPercentage(Enum):
  DEFAULT = 0
  ADMIN = 80
  APP_OWNER = 50