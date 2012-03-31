# -*- coding: utf-8 -*-

"""Provides authenticate, authorize and callback views and a failed view to
  redirect to when OAuth fails, e.g.: when Twitter is down.
"""

import logging
logger = logging.getLogger(__name__)

import tweepy

from pyramid.httpexceptions import HTTPFound, HTTPUnauthorized
from pyramid.security import forget, remember
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC
from pyramid.view import view_config
from zope.interface.registry import ComponentLookupError

from pyramid_simpleauth import events, schema, model as simpleauth_model

from .hooks import get_handler
from .model import get_existing_twitter_account, TwitterAccount

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
    """"""
    
    # Get the verifier value from the request query string.
    verifier = request.GET.get('oauth_verifier')
    # Pop the request token from the session, where we saved it earlier.
    request_token_key = request.session['twitter_request_token_key']
    request_token_secret = request.session['twitter_request_token_secret']
    del request.session['twitter_request_token_key']
    del request.session['twitter_request_token_secret']
    # Exchange the request token for an access token.
    auth = handler_factory(request)
    auth.set_request_token(request_token_key, request_token_secret)
    return_value = _attempt_twitter_call(auth.get_access_token, verifier)
    if isinstance(return_value, HTTPFound):
        return return_value
    # Get the authenticated user's Twitter details.
    client = Api(auth)
    return_value = _attempt_twitter_call(client.verify_credentials)
    if isinstance(return_value, HTTPFound):
        return return_value
    # If authentication was unsuccessful, OAuth failed.
    if return_value is False:
        url = request.route_url('twitterauth', traverse=('failed',))
        return HTTPFound(location=url)
    # Otherwise we got a Twitter user.
    twitter_user = return_value
    # If we don't have a matching user, sign the user up.
    existing = get_existing_twitter_account(twitter_user.id)
    if existing:
        twitter_account = existing
        user = twitter_account.user
    else:
        twitter_account = TwitterAccount()
        twitter_account.twitter_id = twitter_user.id
        twitter_account.screen_name = twitter_user.screen_name
        # XXX can we get the access level from the access token request header?
        # see current logging in tweepy auth line 124
        raise NotImplementedError('twitter_account.access_permission')
        user = simpleauth_model.User()
        user.username = twitter_user.screen_name
        user.twitter_account = twitter_account
        # XXX what if we have a user that's got the twitter username?
        raise NotImplementedError('existing user with username == screen name?')
    # Update the access token.
    twitter_account.oauth_token = auth.access_token.key
    twitter_account.oauth_token_secret = auth.access_token.secret
    # Log the user in.
    headers = remember(request, user.canonical_id)
    # If this was a sign up.
    if not existing:
        # Save the user and twitter_account to the db.
        model.save(user)
        # Fire a ``UserSignedUp`` event.
        request.registry.notify(events.UserSignedUp(request, user))
        # Get the default url to redirect to.
        settings = request.registry.settings
        route_name = settings.get('simpleauth.after_signup_route', 'users')
    # Otherwise it was a login.
    else:
        # Save the twitter_account to the db.
        model.save(twitter_account)
        # Get the default url to redirect to.
        settings = request.registry.settings
        route_name = settings.get('simpleauth.after_login_route', 'index')
    # Fire a ``UserLoggedIn`` event.
    request.registry.notify(events.UserLoggedIn(request, user))
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

