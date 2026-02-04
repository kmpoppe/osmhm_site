from requests_oauthlib import OAuth2Session
from pyramid.view import view_config
from xml.etree import ElementTree
from pyramid.httpexceptions import HTTPFound, HTTPBadGateway, HTTPBadRequest

from ..models import (
    DBSession,
    User,
)

from pyramid.security import (
    remember,
    forget,
)

from urllib.parse import parse_qsl
import oauth2 as oauth

CLIENT_ID        = '4CydJZAh0ZwWYZ_i8vxHwgwGVHyCGw2xmZvOLElscto'
CLIENT_SECRET    = 'xpzk51rLt5MOl97-vA1VYnbeOpVxxxAmkjEMP9nMYXI'

BASE_URL         = 'https://www.openstreetmap.org/oauth2'
TOKEN_URL        = '%s/token' % BASE_URL
AUTHORIZE_URL    = '%s/authorize' % BASE_URL

SCOPE            = [ "read_prefs" ]
REDIRECT_URI     = "https://172.29.164.150/oauth_callback"
USER_DETAILS_URL = 'https://api.openstreetmap.org/api/0.6/user/details'

@view_config(route_name='login')
def login(request):

    osm = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, scope=SCOPE)
    authorization_url, state = osm.authorization_url(AUTHORIZE_URL)

    # store state in session to validate callback
    request.session['oauth_state'] = state
    request.session['came_from'] = request.params.get('came_from')

    return HTTPFound(location=authorization_url)

@view_config(route_name='oauth_callback')
def oauth_callback(request):
    session = request.session
    state = session.get('oauth_state')

    osm = OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, state=state)

    # Fetch the access token using the authorization code from the callback
    callback_url = request.route_url(
        'oauth_callback',
        _scheme='https',
        _port=443
    ) + '?' + request.query_string

    token = osm.fetch_token(
        TOKEN_URL,
        client_secret=CLIENT_SECRET,
        authorization_response=callback_url
    )

    access_token = token.get('access_token')
    if not access_token:
        return HTTPBadRequest('Failed to obtain access token from OSM')

    # Use Bearer token to fetch user details
    headers = {'Authorization': f'Bearer {access_token}'}
    resp = osm.get(USER_DETAILS_URL, headers=headers)
    user_elt = ElementTree.fromstring(resp.content).find('user')

    if 'id' not in user_elt.attrib:
        return HTTPBadRequest('Failed to retrieve user information from OSM')

    userid = user_elt.attrib['id']
    username = user_elt.attrib['display_name']

    # ======== Database logic (mostly unchanged) ========
    user = DBSession.query(User).get(userid)
    if user is None:
        user = User(userid, username)
        DBSession.add(user)
        DBSession.flush()

    # Ensure the first user becomes owner
    if DBSession.query(User).filter(User.role == User.role_owner).count() == 0:
        user.role = User.role_owner

    # Set session cookie
    headers = remember(request, userid, max_age=20 * 7 * 24 * 60 * 60)
    location = session.get('came_from') or request.route_path('home')

    return HTTPFound(location=location, headers=headers)

@view_config(route_name='logout')
def logout(request):  # pragma: no cover
    headers = forget(request)
    return HTTPFound(location=request.route_path('home'), headers=headers)
