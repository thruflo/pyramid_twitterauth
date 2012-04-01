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
from pyramid.view import view_config
from zope.interface.registry import ComponentLookupError

from pyramid_simpleauth import events, schema, model as simpleauth_model

from .hooks import get_handler
from .model import get_existing_twitter_account, TwitterAccount

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

def _do_oauth_redirect(request, is_signin, handler_factory=get_handler):
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
          >>> mock_request.session['twitter_oauth_is_signin']
          True
      
      If there's a ``next`` param in the request, stores that too::
      
          >>> mock_request.params = {'next': '/foo/bar'}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_request.session.get('twitter_oauth_next_url')
          u'/foo/bar'
      
      As long as it's a valid path::
      
          >>> mock_request.session = {}
          >>> mock_request.params = {'next': '<script src="javascript:h@x();">'}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_request.session.get('twitter_oauth_next_url')
      
      Gets a request token from Twitter::
      
          >>> mock_request.params = {}
          >>> mock_request.session = {}
          >>> return_value = _do_oauth_redirect(mock_request, True,
          ...         handler_factory=mock_handler_factory)
          >>> mock_handler_factory.assert_called_with(mock_request)
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
    
    # Store whether this OAuth attempt is a signin or not.
    request.session['twitter_oauth_is_signin'] = is_signin
    # If there was a valid ``next`` param in the query string, store that too.
    next_ = request.params.get('next', request.POST.get('next'))
    try:
        next_ = schema.RequestPath.to_python(next_)
    except schema.Invalid as err:
        next_ = None
    if next_:
        request.session['twitter_oauth_next_url'] = next_
    # Initialise an OAuth handler with the right consumer settings.
    oauth_handler = handler_factory(request)
    # Try and get a request token from Twitter.
    kwargs = dict(signin_with_twitter=is_signin)
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


@view_config(route_name="twitterauth", name='authenticate', permission=PUBLIC)
def oauth_authenticate_view(request, do_redirect=_do_oauth_redirect):
    """Redirect to GET oauth/authenticate.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_do_redirect = Mock()
          >>> mock_do_redirect.return_value = 'http found'
      
      Test::
      
          >>> oauth_authenticate_view(mock_request, do_redirect=mock_do_redirect)
          'http found'
          >>> mock_do_redirect.assert_called_with(mock_request, True)
      
    """
    
    return do_redirect(request, True)


@view_config(route_name="twitterauth", name='authorize', permission=PUBLIC)
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


@view_config(route_name="twitterauth", name='callback', permission=PUBLIC)
def oauth_callback_view(request, handler_factory=get_handler, Api=tweepy.API):
    """Callback view the user is sent back to in order to complete the OAuth
      dance after authorizing (or denying) the app on the Twitter website.
      
      Handles the following failure scenarios:
      
      * the user denied our app
      * our call to the Twitter API to convert our stored request token into
        an access token fails (for example, because Twitter is over capacity)
      * our call to the Twitter API to verify the user's credentials (and thus
        find out who they are) fails
      * the user's credentials are not verified, i.e.: for some strange reason
        the access token we got doesn't actually work
      
      And the following success scenarios:
      
      * update the access token we have on record for the authenticated user
      * associate a twitter account with the authenticated user
      * login an existing user through their existing twitter account
      * signup a new user with a related twitter account
      
    """
    
    # Get the verifier and / or denied values from the request query string.
    verifier = request.GET.get('oauth_verifier')
    denied = request.GET.get('denied')
    
    # Get the next_url and is_signin flag from the session.
    is_signin = request.session.get('twitter_oauth_is_signin')
    next_url = request.session.get('twitter_oauth_next_url')
    
    # Pop the request token from the session, where we saved it earlier.
    request_token_key = request.session['twitter_request_token_key']
    request_token_secret = request.session['twitter_request_token_secret']
    del request.session['twitter_request_token_key']
    del request.session['twitter_request_token_secret']
    
    # If the user chose not to authorize the app, throw the appropriate
    # HTTP exception.
    if denied:
        HTTPException = HTTPUnauthorized if is_signin else HTTPForbidden
        return HTTPException()
    
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
    
    # Get the access permission level from the last_response.
    access_permission = client.last_response.getheader('X-Access-Level')
    
    # If the credentials were not verified, throw the appropriate exception.
    if twitter_user is False:
        HTTPException = HTTPUnauthorized if is_signin else HTTPForbidden
        return HTTPException()
    
    # Get or create the twitter account instance corresponding to ``twitter_user``
    # and update the access token.
    twitter_account = get_existing_twitter_account(twitter_user.id)
    if not twitter_account:
        twitter_account = TwitterAccount()
        twitter_account.twitter_id = twitter_user.id
        twitter_account.screen_name = twitter_user.screen_name
    twitter_account.oauth_token = oauth_handler.access_token.key
    twitter_account.oauth_token_secret = oauth_handler.access_token.secret
    twitter_account.access_permission = access_permission
    
    # If we have a ``request.user`` we relate the twitter account to that user.
    if request.user:
        twitter_account.user = request.user
    
    # If this is a signup and the twitter account isn't related to a user
    # (either when created previously or just now above) then create a user
    # with ``screen_name`` as their username.
    new_user = None
    if not twitter_account.user:
        if not is_signin:
            return HTTPUnauthorized()
        new_user = simpleauth_model.User()
        # XXX note that this currently creates a namespace clash between users
        # who sign up through some other route and users who sign up through
        # Twitter.  This limits the utility of the package to either or rather
        # than both. 
        new_user.username = twitter_user.screen_name
        twitter_account.user = new_user
    
    # Save to the db.
    simpleauth_model.save(twitter_account)
    
    # XXX should we provide additional info in events / fire custom events for
    # e.g.: Twitter signup and Twitter authorise? This way app devs can easily
    # pick up on users connecting a twitter account for the first time?
    
    # Log the user in.
    user = twitter_account.user
    headers = remember(request, user.canonical_id)
    
    # Notify and get the name of the route to redirect to if a ``next`` param
    # hasn't been stored in the session.
    if new_user:
        request.registry.notify(events.UserSignedUp(request, user))
        settings = request.registry.settings
        route_name = settings.get('simpleauth.after_signup_route', 'users')
    else:
        request.registry.notify(events.UserLoggedIn(request, user))
        settings = request.registry.settings
        route_name = settings.get('simpleauth.after_login_route', 'index')
    
    # Work out where to redirect to next.
    next_ = request.session.get('twitter_oauth_next_url')
    if next_:
        location = next_
    else:
        try:
            location = request.route_url(route_name, traverse=(user.username,))
        except (KeyError, ComponentLookupError):
            location = '/'
    
    # Redirect.
    return HTTPFound(location=location, headers=headers)


@view_config(route_name="twitterauth", name='failed', permission=PUBLIC,
        renderer='pyramid_twitterauth:templates/failed.mako')
def oauth_failed_view(request):
    """Render a page explaining that Twitter Auth failed, with a link to try
      again, e.g.: after a few seconds when Twitter is back up and working.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
      
      Redirects to authenticate if is a signin and adds a ``next`` param to the
      redirect url if stored in the session::
      
          >>> mock_request.session = {
          ...     'twitter_oauth_is_signin': True,
          ...     'twitter_oauth_next_url': '/next'
          ... }
          >>> return_value = oauth_failed_view(mock_request)
          >>> kwargs = {
          ...     'traverse': ('authenticate',),
          ...     'query': (('next', '/next'),)
          ... }
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
      
      Redirects to authorize if not a signin::
      
          >>> mock_request.session = {
          ...     'twitter_oauth_is_signin': False,
          ...     'twitter_oauth_next_url': None
          ... }
          >>> return_value = oauth_failed_view(mock_request)
          >>> kwargs = {
          ...     'traverse': ('authorize',),
          ...     'query': ()
          ... }
          >>> mock_request.route_url.assert_called_with('twitterauth', **kwargs)
      
    """
    
    # Work out which view to link to.
    is_signin = request.session.get('twitter_oauth_is_signin')
    traverse = ('authenticate',) if is_signin else ('authorize',)
    
    # If stored in the session, add a ``next`` param.
    next_url = request.session.get('twitter_oauth_next_url')
    query = (('next', next_url),) if next_url else ()
    
    # Generate the try again url.
    url = request.route_url('twitterauth', traverse=traverse, query=query)
    return {'try_again_url': url}

