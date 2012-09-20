# -*- coding: utf-8 -*-

"""Provides authenticate, authorize and callback views and a failed view to
  redirect to when OAuth fails, e.g.: when Twitter is down.
"""

import logging
logger = logging.getLogger(__name__)

import tweepy

from pyramid.httpexceptions import HTTPForbidden, HTTPFound, HTTPUnauthorized
from pyramid.security import forget, remember, unauthenticated_userid
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC
from zope.interface.registry import ComponentLookupError

from pyramid_basemodel import save as save_to_db
from pyramid_simpleauth.events import UserSignedUp, UserLoggedIn
from pyramid_simpleauth.schema import Invalid, RequestPath
from pyramid_simpleauth.model import User

from .hooks import get_handler
from .model import get_existing_twitter_account, TwitterAccount, TwitterProfile

def forbidden_view(request):
    """Handle a user being denied access to a resource or view by redirecting
      to authenticate via Twitter.  See the ``pyramid_twitterauth.includeme``
      function for info on how to expose this view.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_twitterauth import view
          >>> _unauthenticated_userid = view.unauthenticated_userid
          >>> view.unauthenticated_userid = Mock()
          >>> mock_request = Mock()
          >>> mock_request.path = '/forbidden/page'
          >>> mock_request.route_url.return_value = '/oauth/twitter/authenticate'
      
      If the user is already logged in, it means they don't have the requisit
      permission, so we raise a 403 Forbidden error::
      
          >>> view.unauthenticated_userid.return_value = 1234
          >>> response = forbidden_view(mock_request)
          >>> response.status
          '403 Forbidden'
      
      Otherwise we redirect to the authenticate view::
      
          >>> view.unauthenticated_userid.return_value = None
          >>> response = forbidden_view(mock_request)
          >>> kwargs = {
          ...     '_query': (('next', '/forbidden/page'),),
          ...     'traverse': ('authenticate',)
          ... }
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
          >>> response.location
          '/oauth/twitter/authenticate'
          >>> response.status
          '302 Found'
      
      Teardown::
      
          >>> view.unauthenticated_userid = _unauthenticated_userid
      
    """
    
    if unauthenticated_userid(request):
        return HTTPForbidden()
    query = (('next', request.path),)
    url = request.route_url('twitterauth', traverse=('authenticate',), _query=query)
    return HTTPFound(location=url)


def _redirect_to_failed(request, redirect_cls=HTTPFound):
    """Redirect to the failed view.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_request.route_url.return_value = 'redirect url'
          >>> mock_redirect_cls = Mock()
          >>> mock_redirect_cls.return_value = 'http found'
      
      Test::
      
          >>> _redirect_to_failed(mock_request, redirect_cls=mock_redirect_cls)
          'http found'
          >>> kwargs = dict(traverse=('failed',))
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
          >>> mock_redirect_cls.assert_called_with(location='redirect url')
      
    """
    
    url = request.route_url('twitterauth', traverse=('failed',))
    return redirect_cls(location=url)

def _do_oauth_redirect(request, is_authenticate, handler_factory=get_handler):
    """Start the OAuth dance by getting a request token from the Twitter API,
      storing it in the session and then redirecting to Twitter.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_request.session = {}
          >>> mock_handler = Mock()
          >>> mock_handler.get_authorization_url.return_value = 'url'
          >>> mock_handler.request_token.key = 'key'
          >>> mock_handler.request_token.secret = 'secret'
          >>> mock_handler_factory = Mock()
          >>> mock_handler_factory.return_value = mock_handler
      
      Stores whether this OAuth attempt is a signin or not::
      
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_request.session['twitter_oauth_is_authenticate']
          True
      
      If there's a ``next`` param in the request, stores that too::
      
          >>> mock_request.params = {'next': '/foo/bar'}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_request.session.get('twitter_oauth_next')
          u'/foo/bar'
      
      As long as it's a valid path::
      
          >>> mock_request.session = {}
          >>> mock_request.params = {'next': '<script src="javascript:h@x();">'}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_request.session.get('twitter_oauth_next')
      
      Gets a request token from Twitter::
      
          >>> mock_request.params = {}
          >>> mock_request.session = {}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> kwargs = dict(callback='authenticate_callback')
          >>> mock_handler_factory.assert_called_with(mock_request, **kwargs)
          >>> kwargs = dict(signin_with_twitter=True)
          >>> mock_handler.get_authorization_url.assert_called_with(**kwargs)
      
      Stores it in the session::
      
          >>> mock_request.session.get('twitter_request_token_key')
          'key'
          >>> mock_request.session.get('twitter_request_token_secret')
          'secret'
      
      Redirects to the authorisation url::
      
          >>> return_value.location
          'url'
      
    """
    
    # Store whether this OAuth attempt is to authenticate or authorize, so we
    # can provide the right try again link in case any of our calls to the
    # Twitter API fail.
    request.session['twitter_oauth_is_authenticate'] = is_authenticate
    # If there was a valid ``next`` param in the query string, store it in the
    # session so we can redirect to it later on.
    next_ = request.params.get('next')
    try:
        request.session['twitter_oauth_next'] = RequestPath.to_python(next_)
    except Invalid:
        pass
    # Initialise an OAuth handler with the right consumer settings.
    if is_authenticate:
        callback_view = 'authenticate_callback'
    else:
        callback_view = 'authorize_callback'
    oauth_handler = handler_factory(request, callback=callback_view)
    # Try and get a request token from Twitter.
    kwargs = dict(signin_with_twitter=is_authenticate)
    try:
        redirect_url = oauth_handler.get_authorization_url(**kwargs)
    except tweepy.TweepError:
        return _redirect_to_failed(request)
    # Store the request token in the session.
    token = oauth_handler.request_token
    request.session['twitter_request_token_key'] = token.key
    request.session['twitter_request_token_secret'] = token.secret
    # Redirect.
    return HTTPFound(location=redirect_url)

def _get_redirect_url(request, action, candidate_next, user=None):
    """Get URL to redirect to after ``action``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_request.route_url.return_value = 'url'
          >>> mock_request.registry.settings.get.return_value = 'route name'
      
      Called with a valid next, returns it::
      
          >>> _get_redirect_url(mock_request, 'login', '/bar') # Valid
          u'/bar'
      
      Called with an invalid next doesn't::
      
          >>> _get_redirect_url(mock_request, 'login', '://') == u'://'
          False
      
      If action is 'login', tries to get the ``after_login_route``::
      
          >>> return_value = _get_redirect_url(mock_request, 'login', None)
          >>> get = mock_request.registry.settings.get
          >>> get.assert_called_with('simpleauth.after_login_route', 'index')
          >>> mock_request.route_url.assert_called_with('route name', traverse=())
          >>> return_value
          'url'
      
      With the user.username in the traverse if a user is provided::
      
          >>> mock_user = Mock()
          >>> _ = _get_redirect_url(mock_request, 'login', None, user=mock_user)
          >>> mock_request.route_url.assert_called_with('route name', 
          ...         traverse=(mock_user.username,))
      
      If action is 'signup', tries to get the ``after_signup_route``::
      
          >>> return_value = _get_redirect_url(mock_request, 'signup', None)
          >>> get = mock_request.registry.settings.get
          >>> get.assert_called_with('simpleauth.after_signup_route', 'users')
      
      If 'connect', tries to get the ``after_connect_route``::
      
          >>> return_value = _get_redirect_url(mock_request, 'connect', None)
          >>> get = mock_request.registry.settings.get
          >>> get.assert_called_with('twitterauth.after_connect_route', 'users')
      
      If the route isn't configured, falls back on '/'::
      
          >>> def raise_err(*args, **kwargs):
          ...     raise ComponentLookupError
          ... 
          >>> mock_request.route_url = raise_err
          >>> _get_redirect_url(mock_request, 'signup', None)
          '/'
      
    """
    
    # If we've been provided a valid next value, return that.
    if candidate_next:
        try:
            return RequestPath.to_python(candidate_next)
        except Invalid:
            pass
    # Otherwise get the route url to redirect to.
    settings = request.registry.settings
    if action == 'login':
        key = 'simpleauth.after_login_route'
        default = 'index'
    elif action == 'signup':
        key = 'simpleauth.after_signup_route'
        default = 'users'
    elif action == 'connect':
        key = 'twitterauth.after_connect_route'
        default = 'users'
    route_name = settings.get(key, default)
    traverse = (user.username,) if user else ()
    try:
        # If the route exists, use that URL.
        return request.route_url(route_name, traverse=traverse)
    except (KeyError, ComponentLookupError):
        # Otherwise as a last resort fall back on '/'.
        return '/'

def _unpack_callback(request, handler_factory=get_handler, Api=tweepy.API):
    """Get a Twitter user, OAuth handler and access permission from an OAuth
      callback request.  Returns a tuple of::
      
          twitter_user, oauth_handler, access_permission
      
      Handles the following failure scenarios:
      
      * the user denied our app
      * our call to the Twitter API to convert our stored request token into
        an access token fails (for example, because Twitter is over capacity)
      * our call to the Twitter API to verify the user's credentials (and thus
        find out who they are) fails
      * the user's credentials are not verified, i.e.: for some strange reason
        the access token we got doesn't actually work
      
    """
    
    # If the user chose not to authorize the app, redirect to the failed view.
    if request.GET.get('denied'):
        return _redirect_to_failed(request)
    # Get the verifier and / or denied values from the request query string
    # and pop the request token from the session, where we saved it earlier.
    verifier = request.GET.get('oauth_verifier')
    request_token_key = request.session['twitter_request_token_key']
    request_token_secret = request.session['twitter_request_token_secret']
    del request.session['twitter_request_token_key']
    del request.session['twitter_request_token_secret']
    # Exchange the request token for an access token.
    oauth_handler = handler_factory(request)
    oauth_handler.set_request_token(request_token_key, request_token_secret)
    try:
        oauth_handler.get_access_token(verifier)
    except tweepy.TweepError:
        return _redirect_to_failed(request)
    # Get the authenticated user's Twitter details.
    client = Api(oauth_handler)
    try:
        twitter_user = client.verify_credentials()
    except tweepy.TweepError:
        return _redirect_to_failed(request)
    # If the credentials were not verified, redirect to the failed view.
    if twitter_user is False:
        return _redirect_to_failed(request)
    # Get the access permission level from the last_response.
    access_permission = client.last_response.getheader('X-Access-Level')
    # Return unpacked elements.
    return twitter_user, oauth_handler, access_permission


def oauth_authenticate_view(request, do_redirect=_do_oauth_redirect):
    """Redirect to GET oauth/authenticate.
      
      Setup::
      
          >>> from mock import Mock
          >>> from pyramid_twitterauth import view
          >>> _get_redirect_url = view._get_redirect_url
          >>> view._get_redirect_url = Mock()
          >>> view._get_redirect_url.return_value = 'redirect url'
          >>> mock_request = Mock()
          >>> mock_request.is_authenticated = False
          >>> mock_do_redirect = Mock()
          >>> mock_do_redirect.return_value = 'twitter api'
      
      Redirects to Twitter::
      
          >>> oauth_authenticate_view(mock_request, do_redirect=mock_do_redirect)
          'twitter api'
          >>> mock_do_redirect.assert_called_with(mock_request, True)
      
      Unless called with an authenticated user::
      
          >>> mock_do_redirect = Mock()
          >>> mock_request.is_authenticated = True
          >>> oauth_authenticate_view(mock_request, do_redirect=mock_do_redirect)
          'redirect url'
          >>> mock_do_redirect.called
          False
      
      Teardown::
      
          >>> view._get_redirect_url = _get_redirect_url
      
    """
    
    # If there's already an authenticated user, we don't need to authenticate.
    if request.is_authenticated:
        return _get_redirect_url(request, 'login', request.params.get('next'))
    return do_redirect(request, True)

def oauth_authorize_view(request, do_redirect=_do_oauth_redirect):
    """Redirect to GET oauth/authorize.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_do_redirect = Mock()
          >>> mock_do_redirect.return_value = 'http found'
      
      Test::
      
          >>> oauth_authorize_view(mock_request, do_redirect=mock_do_redirect)
          'http found'
          >>> mock_do_redirect.assert_called_with(mock_request, False)
      
    """
    
    return do_redirect(request, False)


def authenticate_callback_view(request, unpack=_unpack_callback):
    """Complete the OAuth dance after a user has authenticated the app."""
    
    # This view should not be called by an authenticated user.
    if request.is_authenticated:
        return HTTPForbidden()
    
    # Unpack the request.
    return_value = unpack(request)
    if isinstance(return_value, HTTPFound):
        return return_value
    twitter_user, oauth_handler, access_permission = return_value
    # If there is an existing ``twitter_account`` then this is a login, so
    # update the ``twitter_account`` and generate a login event.
    existing = get_existing_twitter_account(twitter_user.id)
    if existing:
        twitter_account = existing
        twitter_account.profile.set_data_from_tweepy_user(twitter_user)
        user = twitter_account.user
        event = UserLoggedIn(request, user, data=twitter_user)
        action = 'login'
    else: # Otherwise, this is a signup, so insert a new ``user`` with a
        # ``twitter_account`` and generate a signup event.
        user = User()
        user.username = twitter_user.screen_name
        twitter_account = TwitterAccount()
        twitter_account.twitter_id = twitter_user.id
        twitter_account.user = user
        twitter_account.profile = TwitterProfile.create_from_tweepy_user(twitter_user)
        event = UserSignedUp(request, user, data=twitter_user)
        action = 'signup'
    # Update the twitter_account with the latest data, save to the db and
    # actually fire the event.
    twitter_account.screen_name = twitter_user.screen_name
    twitter_account.oauth_token = oauth_handler.access_token.key
    twitter_account.oauth_token_secret = oauth_handler.access_token.secret
    twitter_account.access_permission = access_permission
    save_to_db(twitter_account) # <!-- this saves the user along with it.
    request.registry.notify(event)
    # Actually log the user in and then redirect to the appropriate location.
    next_ = request.session.get('twitter_oauth_next')
    location = _get_redirect_url(request, action, next_, user=user)
    headers = remember(request, user.canonical_id)
    return HTTPFound(location=location, headers=headers)

def authorize_callback_view(request, unpack=_unpack_callback):
    """Complete the OAuth dance after a user has authorized the app."""
    
    # This callback should not be called to handle login or signup.
    if request.session.get('twitter_oauth_is_authenticate'):
        return HTTPForbidden()
    # Unpack the request.
    return_value = unpack(request)
    if isinstance(return_value, HTTPFound):
        return return_value
    twitter_user, oauth_handler, access_permission = return_value
    # Update or create the ``twitter_account`` corresponding to ``twitter_user``,
    # relate it to the current ``request.user`` and save to the db.
    twitter_account = get_existing_twitter_account(twitter_user.id)
    if not twitter_account:
        twitter_account = TwitterAccount()
        twitter_account.twitter_id = twitter_user.id
    twitter_account.screen_name = twitter_user.screen_name
    twitter_account.oauth_token = oauth_handler.access_token.key
    twitter_account.oauth_token_secret = oauth_handler.access_token.secret
    twitter_account.access_permission = access_permission
    twitter_account.user = request.user
    save_to_db(twitter_account)
    # Redirect to the appropriate location.
    next_ = request.session.get('twitter_oauth_next')
    location = _get_redirect_url(request, 'connect', next_, user=request.user)
    return HTTPFound(location=location)


def oauth_failed_view(request):
    """Render a page explaining that Twitter Auth failed, with a link to try
      again, e.g.: after a few seconds when Twitter is back up and working.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
      
      Redirects to authenticate if is a signin and adds a ``next`` param to the
      redirect url if stored in the session::
      
          >>> mock_request.session = {
          ...     'twitter_oauth_is_authenticate': True,
          ...     'twitter_oauth_next': '/next'
          ... }
          >>> return_value = oauth_failed_view(mock_request)
          >>> kwargs = {
          ...     'traverse': ('authenticate',),
          ...     'query': (('next', '/next'),)
          ... }
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
      
      Redirects to authorize if not a signin::
      
          >>> mock_request.session = {
          ...     'twitter_oauth_is_authenticate': False,
          ...     'twitter_oauth_next': None
          ... }
          >>> return_value = oauth_failed_view(mock_request)
          >>> kwargs = {
          ...     'traverse': ('authorize',),
          ...     'query': ()
          ... }
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
      
    """
    
    # Work out which view to link to.
    is_authenticate = request.session.get('twitter_oauth_is_authenticate')
    traverse = ('authenticate',) if is_authenticate else ('authorize',)
    
    # If stored in the session, add a ``next`` param.
    next_url = request.session.get('twitter_oauth_next')
    query = (('next', next_url),) if next_url else ()
    
    # Generate the try again url.
    url = request.route_url('twitterauth', traverse=traverse, query=query)
    return {'try_again_url': url}

