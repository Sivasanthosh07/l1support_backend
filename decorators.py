import logging
from flask import request


def validate_access_token(method_to_decorate):
    """Decorator method to check whether user access token passed in header of Request

    :param method_to_decorate: Method to decorate
    :type method_to_decorate: function
    """
    def wrapper(*args, **kwargs):
        user_access_token = request.headers.get('Authorization', '').split(' ')
        if len(user_access_token) == 2 and user_access_token[1]:
            return method_to_decorate(*args, **kwargs)
        else:
            logging.warning(
                "No user access_token present in the request header.")
            return {
                'status': 'failed',
                'message': 'Something went wrong.',
                'error': 'No access token present in the request'
            }, 401
    wrapper.__name__ = method_to_decorate.__name__
    return wrapper
