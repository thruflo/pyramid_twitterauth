# -*- coding: utf-8 -*-

"""Integration and functional tests for ``pyramid_twitterauth``."""

import unittest

try: # pragma: no cover
    from webtest import TestApp, TestRequest, TestResponse
except ImportError: # pragma: no cover
    pass

def config_factory(is_authenticated=False, **settings):
    """Call with settings to make and configure a configurator instance, binding
      to an in memory db.
    """
    
    from pyramid.config import Configurator
    from pyramid.session import UnencryptedCookieSessionFactoryConfig
    
    # Patch the settings to use an in memory db for testing, which should
    # be dropped every time the app is created.
    settings['sqlalchemy.url'] = 'sqlite:///:memory:'
    settings['basemodel.should_drop_all'] = True
    # Patch the settings to use a dummy app to connect to Twitter.
    key = 'xZNXRgs8oqEcHOBxf4vpw'
    secret = 'E9G2yBiyvp16rZ9hh3QhOe5MXU1Ecwo2LIYEbLbHdto'
    settings['twitterauth.oauth_consumer_key'] = key
    settings['twitterauth.oauth_consumer_secret'] = secret
    if is_authenticated:
        settings['simpleauth.set_default_permission'] = False
    # Initialise the ``Configurator`` and setup a session factory.
    config = Configurator(settings=settings)
    config.set_session_factory(UnencryptedCookieSessionFactoryConfig('psst'))
    # Include the dependencies.
    config.include('pyramid_tm')
    config.include('pyramid_simpleauth')
    config.commit()
    config.include('pyramid_twitterauth')
    config.include('pyramid_basemodel')
    # Fake authentication if need be.
    if is_authenticated:
        config.registry.settings['simpleauth.set_default_permission']
        from pyramid_simpleauth.model import User
        return_true = lambda request: True
        return_user = lambda request: User()
        config.set_request_property(return_true, 'is_authenticated', reify=True)
        config.set_request_property(return_user, 'user', reify=True)
    # Return the configurator instance.
    return config

class TestUnpackCallback(unittest.TestCase):
    """Integration tests for ``view._unpack_callback``."""
    
    def setUp(self):
        from mock import Mock
        mock_request = Mock()
        mock_request.GET = {}
        mock_request.session = {
            'twitter_request_token_key': 'key',
            'twitter_request_token_secret': 'secret',
        }
        self.request = mock_request
        self.request.route_url.return_value = '/'
        # Setup mock oauth handler and tweepy client.
        self.mock_handler_factory = Mock()
        self.mock_handler = Mock()
        self.mock_handler.access_token.key = 'key'
        self.mock_handler.access_token.secret = 'secret'
        self.mock_handler_factory.return_value = self.mock_handler
        self.mock_api_factory = Mock()
        self.mock_client = Mock()
        self.mock_client.last_response.getheader.return_value = 'read'
        self.mock_api_factory.return_value = self.mock_client
    
    def makeOne(self, *args, **kwargs):
        """Call the OAuth callback view and return the response."""
        
        from pyramid_twitterauth.view import _unpack_callback
        return _unpack_callback(*args, **kwargs)
    
    def assertRedirectedToFailed(self, response):
        from pyramid.httpexceptions import HTTPFound
        kwargs = dict(traverse=('failed',))
        self.request.route_url.assert_called_with('twitterauth', **kwargs)
        self.assertTrue(isinstance(response, HTTPFound))
    
    def test_denied(self):
        """Redirects to the failed view if the user denied our app."""
        
        self.request.GET['denied'] = 'abcd'
        response = self.makeOne(self.request)
        self.assertRedirectedToFailed(response)
    
    def test_convert_to_access_token_fails(self):
        """If our call to the Twitter API to convert our stored request token into
          an access token fails (for example, because Twitter is over capacity),
          redirects to the failed view.
        """
        
        import tweepy
        def raise_tweepy_error(*args, **kwargs):
            raise tweepy.TweepError('a')
        
        self.mock_handler.get_access_token = raise_tweepy_error
        response = self.makeOne(self.request, handler_factory=self.mock_handler_factory)
        self.assertRedirectedToFailed(response)
    
    def test_verify_credentials_fails(self):
        """If our call to the Twitter API to verify the user's credentials (and thus
          find out who they are) fails, redirects to the failed view.
        """
        
        import tweepy
        def raise_tweepy_error(*args, **kwargs):
            raise tweepy.TweepError('a')
        
        self.mock_client.verify_credentials = raise_tweepy_error
        response = self.makeOne(self.request, handler_factory=self.mock_handler_factory,
                Api=self.mock_api_factory)
        self.assertRedirectedToFailed(response)
    
    def test_verify_credentials_false(self):
        """Redirects to the failed view if the user's credentials aren't valid."""
        
        self.mock_client.verify_credentials.return_value = False
        response = self.makeOne(self.request, handler_factory=self.mock_handler_factory,
                Api=self.mock_api_factory)
        self.assertRedirectedToFailed(response)
    
    def test_returns_tuple_of_unpacked_elements(self):
        """Returns ``twitter_user, oauth_handler, access_permission``."""
        
        self.mock_client.verify_credentials.return_value = 'twitter user'
        self.mock_client.last_response.getheader.return_value = 'access permission'
        data = self.makeOne(self.request, handler_factory=self.mock_handler_factory,
                Api=self.mock_api_factory)
        self.assertTrue(data[0] == 'twitter user')
        self.assertTrue(data[1] == self.mock_handler)
        self.assertTrue(data[2] == 'access permission')
    

class TestAuthenticateCallback(unittest.TestCase):
    """Integration tests for ``view.authenticate_callback_view``.
    """
    
    def setUp(self):
        from mock import Mock
        from pyramid_twitterauth import view
        self._get_existing_twitter_account = view.get_existing_twitter_account
        self._get_redirect_url = view._get_redirect_url
        self._save_to_db = view.save_to_db
        self._remember = view.remember
        view.get_existing_twitter_account = Mock()
        view._get_redirect_url = Mock()
        view.save_to_db = Mock()
        view.remember = Mock()
        mock_request = Mock()
        self.request = mock_request
        self.request.session = {}
        self.request.is_authenticated = False
        self.mock_twitter_account = Mock()
        self.mock_twitter_user = Mock()
        self.mock_twitter_user.id = 1234
        self.mock_twitter_user.screen_name = 'screen name'
        self.mock_oauth_handler = Mock()
        self.mock_oauth_handler.access_token.key = 'key'
        self.mock_oauth_handler.access_token.secret = 'secret'
        self.access_permission = 'read'
        self.mock_unpack_callback = Mock()
        data = (self.mock_twitter_user, self.mock_oauth_handler, self.access_permission)
        self.mock_unpack_callback.return_value = data
        view._get_redirect_url.return_value = 'url'
        view.remember.return_value = {}
    
    def tearDown(self):
        from pyramid_twitterauth import view
        view.get_existing_twitter_account = self._get_existing_twitter_account
        view.save_to_db = self._save_to_db
        view.remember = self._remember
    
    def makeOne(self, request):
        """Call the OAuth callback view and return the response."""
        
        from pyramid_twitterauth.view import authenticate_callback_view
        return authenticate_callback_view(request, unpack=self.mock_unpack_callback)
    
    def test_authenticate_auth_user_forbidden(self):
        """Should not be called by an authenticated user."""
        
        from pyramid.httpexceptions import HTTPForbidden
        
        self.request.is_authenticated = True
        response = self.makeOne(self.request)
        self.assertTrue(isinstance(response, HTTPForbidden))
    
    def test_unpack_fails(self):
        """If unpack returns a redirect, returns it."""
        
        from pyramid.httpexceptions import HTTPFound
        
        redirect = HTTPFound(location='/foo')
        self.mock_unpack_callback.return_value = redirect
        response = self.makeOne(self.request)
        self.assertTrue(response.location == '/foo')
    
    def test_gets_existing_from_twitter_user_id(self):
        """Calls ``get_existing_twitter_account(twitter_user.id)``."""
        
        from pyramid_twitterauth import view
        
        self.mock_twitter_user.id = 1234
        response = self.makeOne(self.request)
        view.get_existing_twitter_account.assert_called_with(1234)
    
    def test_existing_fires_a_login_event(self):
        """If there's an existing twitter account, fires ``UserLoggedIn``."""
        
        from pyramid_twitterauth import view
        from pyramid_simpleauth.events import UserLoggedIn
        
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        event = self.request.registry.notify.call_args[0][0]
        self.assertTrue(isinstance(event, UserLoggedIn))
    
    def test_no_existing_fires_a_signup_event(self):
        """If there's not existing twitter account, fires ``UserSignedUp``."""
        
        from pyramid_twitterauth import view
        from pyramid_simpleauth.events import UserSignedUp
        
        view.get_existing_twitter_account.return_value = None
        response = self.makeOne(self.request)
        event = self.request.registry.notify.call_args[0][0]
        self.assertTrue(isinstance(event, UserSignedUp))
    
    def test_existing_saves_updated_twitter_account(self):
        """If there's an existing twitter account, its updated and saved."""
        
        from pyramid_twitterauth import view
        
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        view.save_to_db.assert_called_with(self.mock_twitter_account)
        
        self.assertTrue(self.mock_twitter_account.screen_name == 'screen name')
        self.assertTrue(self.mock_twitter_account.oauth_token == 'key')
        self.assertTrue(self.mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(self.mock_twitter_account.access_permission == 'read')
    
    def test_existing_doesnt_have_id_or_user_set(self):
        """If there's an existing twitter account, its id and user aren't set."""
        
        from pyramid_twitterauth import view
        from pyramid_simpleauth.model import User
        
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        self.assertFalse(isinstance(self.mock_twitter_account.user, User))
        self.assertFalse(self.mock_twitter_account.twitter_id == 1234)
    
    def test_no_existing_creates_and_saves(self):
        """If there's not an existing twitter account, inserts new 
          ``twitter_account`` and ``user``.
        """
        
        from pyramid_twitterauth import view
        from pyramid_simpleauth.model import User
        
        view.get_existing_twitter_account.return_value = None
        response = self.makeOne(self.request)
        twitter_account = view.save_to_db.call_args[0][0]
        
        self.assertTrue(twitter_account.twitter_id == 1234)
        self.assertTrue(twitter_account.screen_name == 'screen name')
        self.assertTrue(twitter_account.oauth_token == 'key')
        self.assertTrue(twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(twitter_account.access_permission == 'read')
        self.assertTrue(isinstance(twitter_account.user, User))
        self.assertTrue(twitter_account.user.username == 'screen name')
    
    def test_logs_user_in(self):
        """Actually log the user in."""
        
        from pyramid_twitterauth import view
        
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        user = self.mock_twitter_account.user
        view.remember.assert_called_with(self.request, user.canonical_id)
    
    def test_existing_redirects_to_after_login(self):
        """If there's an existing twitter account, gets redirect url for login."""
        
        from pyramid_twitterauth import view
        
        self.request.session['twitter_oauth_next'] = 'next'
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        view._get_redirect_url.assert_called_with(self.request, 'login', 'next')
        self.assertTrue(response.location == 'url')
    
    def test_no_existing_redirects_to_after_signup(self):
        """If there's not an existing twitter account, gets redirect url for signup."""
        
        from pyramid_twitterauth import view
        
        self.request.session['twitter_oauth_next'] = 'next'
        view.get_existing_twitter_account.return_value = None
        response = self.makeOne(self.request)
        view._get_redirect_url.assert_called_with(self.request, 'signup', 'next')
        self.assertTrue(response.location == 'url')
    

class TestAuthorizeCallback(unittest.TestCase):
    """Integration tests for ``view.authorize_callback_view``.
    """
    
    def setUp(self):
        from mock import Mock
        from pyramid_simpleauth.model import User
        from pyramid_twitterauth import view
        self._get_existing_twitter_account = view.get_existing_twitter_account
        self._get_redirect_url = view._get_redirect_url
        self._save_to_db = view.save_to_db
        self._remember = view.remember
        view.get_existing_twitter_account = Mock()
        view._get_redirect_url = Mock()
        view.save_to_db = Mock()
        view.remember = Mock()
        mock_request = Mock()
        self.request = mock_request
        self.request.session = {}
        self.request.is_authenticated = True
        self.request.user = User()
        self.mock_twitter_account = Mock()
        self.mock_twitter_user = Mock()
        self.mock_twitter_user.id = 1234
        self.mock_twitter_user.screen_name = 'screen name'
        self.mock_oauth_handler = Mock()
        self.mock_oauth_handler.access_token.key = 'key'
        self.mock_oauth_handler.access_token.secret = 'secret'
        self.access_permission = 'read'
        self.mock_unpack_callback = Mock()
        data = (self.mock_twitter_user, self.mock_oauth_handler, self.access_permission)
        self.mock_unpack_callback.return_value = data
        view._get_redirect_url.return_value = 'url'
        view.remember.return_value = {}
    
    def tearDown(self):
        from pyramid_twitterauth import view
        view.get_existing_twitter_account = self._get_existing_twitter_account
        view.save_to_db = self._save_to_db
        view.remember = self._remember
    
    def makeOne(self, request):
        """Call the OAuth callback view and return the response."""
        
        from pyramid_twitterauth.view import authorize_callback_view
        return authorize_callback_view(request, unpack=self.mock_unpack_callback)
    
    def test_authenticate_auth_user_forbidden(self):
        """Should not be called after an authentication attempt."""
        
        from pyramid.httpexceptions import HTTPForbidden
        
        self.request.session['twitter_oauth_is_authenticate'] = True
        response = self.makeOne(self.request)
        self.assertTrue(isinstance(response, HTTPForbidden))
    
    def test_unpack_fails(self):
        """If unpack returns a redirect, returns it."""
        
        from pyramid.httpexceptions import HTTPFound
        
        redirect = HTTPFound(location='/foo')
        self.mock_unpack_callback.return_value = redirect
        response = self.makeOne(self.request)
        self.assertTrue(response.location == '/foo')
    
    def test_gets_existing_from_twitter_user_id(self):
        """Calls ``get_existing_twitter_account(twitter_user.id)``."""
        
        from pyramid_twitterauth import view
        
        self.mock_twitter_user.id = 1234
        response = self.makeOne(self.request)
        view.get_existing_twitter_account.assert_called_with(1234)
    
    def test_existing_saves_updated_twitter_account(self):
        """If there's an existing twitter account, its updated, related to
          ``request.user`` and saved.
        """
        
        from pyramid_twitterauth import view
        
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        view.save_to_db.assert_called_with(self.mock_twitter_account)
        
        self.assertTrue(self.mock_twitter_account.screen_name == 'screen name')
        self.assertTrue(self.mock_twitter_account.oauth_token == 'key')
        self.assertTrue(self.mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(self.mock_twitter_account.access_permission == 'read')
        self.assertTrue(self.mock_twitter_account.user == self.request.user)
    
    def test_no_existing_creates_and_saves(self):
        """If there's not an existing twitter account, creates one, sets
          the data, related to ``request.user`` and saves.
        """
        
        from pyramid_twitterauth import view
        
        view.get_existing_twitter_account.return_value = None
        response = self.makeOne(self.request)
        twitter_account = view.save_to_db.call_args[0][0]
        
        self.assertTrue(twitter_account.twitter_id == 1234)
        self.assertTrue(twitter_account.screen_name == 'screen name')
        self.assertTrue(twitter_account.oauth_token == 'key')
        self.assertTrue(twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(twitter_account.access_permission == 'read')
        self.assertTrue(twitter_account.user == self.request.user)
    
    def test_redirects_to_after_connect(self):
        """Gets redirect url for connect."""
        
        from pyramid_twitterauth import view
        
        self.request.session['twitter_oauth_next'] = 'next'
        view.get_existing_twitter_account.return_value = self.mock_twitter_account
        response = self.makeOne(self.request)
        view._get_redirect_url.assert_called_with(self.request, 'connect', 'next')
        self.assertTrue(response.location == 'url')
    

class TestAuthenticateRedirects(unittest.TestCase):
    """Functional tests for the auth views."""
    
    def setUp(self):
        """Configure the Pyramid application."""
        
        self.config = config_factory()
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def test_authenticate(self):
        """A request to the authenticate view should redirect to Twitter."""
        
        res = self.app.post('/oauth/twitter/authenticate', status=302)
        location = res.headers.get('Location')
        twitter_stub = 'https://api.twitter.com/oauth/authenticate?oauth_token='
        self.assertTrue(location.startswith(twitter_stub))
    
    def test_authorize(self):
        """A request to the authorize view will return 404."""
        
        res = self.app.post('/oauth/twitter/authorize', status=404)
    
    def test_invalid_consumer_settings(self):
        """A request to authenticate will redirect to failed if the consumer
          settings are invalid.
        """
        
        settings = self.config.registry.settings
        settings['twitterauth.oauth_consumer_key'] = 'blah'
        settings['twitterauth.oauth_consumer_secret'] = 'wrong'
        res = self.app.post('/oauth/twitter/authenticate', status=302)
        location = res.headers.get('Location')
        self.assertTrue(location=='http://localhost/oauth/twitter/failed')
    
    def test_authenticate_with_twitter_redirects_to_callback(self):
        """After a user authenticates with Twitter, they're redirected to the
          twitterauth callback view.
        """
        
        import urllib, urllib2
        
        # Get the auth url to redirect to.
        res = self.app.get('/oauth/twitter/authenticate', status=302)
        
        # Redirect and parse the response.
        sock = urllib2.urlopen(res.location)
        res = TestResponse()
        res.body = sock.read()
        sock.close()
        
        # Authenticate with our dummy username and password.
        res.form.set('session[username_or_email]', 'pyramid_twauth')
        res.form.set('session[password]', 'pyramid_twitterauth')
        
        # Submit the form and get the new redirect response.
        data = urllib.urlencode(res.form.submit_fields())
        sock = urllib2.urlopen(res.form.action, data)
        text = sock.read()
        sock.close()
        
        # Manually parse the redirect url out of the meta tag.
        l = len('<meta http-equiv="refresh" content="0;url=')
        pos = text.index('<meta http-equiv="refresh" content="0;url=')
        frag = text[pos+l:]
        pos = frag.index('">')
        url = frag[:pos]
        
        # Test that the fragment starts with our callback url.
        stub = 'http://localhost/oauth/twitter/authenticate_callback'
        self.assertTrue(url.startswith(stub))
    

class TestAuthorizeRedirects(unittest.TestCase):
    """Functional tests for the authorize workflow."""
    
    def setUp(self, is_authenticated=True):
        """Configure the Pyramid application."""
        
        settings = {'twitterauth.mode': 'connect'}
        self.config = config_factory(is_authenticated=is_authenticated, **settings)
        self.app = TestApp(self.config.make_wsgi_app())
    
    def tearDown(self):
        """Make sure the session is cleared between tests."""
        
        from pyramid_basemodel import Session
        Session.remove()
    
    def test_authenticate(self):
        """A request to the authenticate view will return 404."""
        
        res = self.app.post('/oauth/twitter/authenticate', status=404)
    
    def test_authorize(self):
        """A request to the authorize view requires authentication and will
          redirect to Twitter.
        """
        
        self.setUp(is_authenticated=False)
        res = self.app.post('/oauth/twitter/authorize', status=302)
        location = res.headers.get('Location')
        auth_stub = 'http://localhost/auth/login?next'
        self.assertTrue(location.startswith(auth_stub))
        
        self.setUp(is_authenticated=True)
        res = self.app.post('/oauth/twitter/authorize', status=302)
        location = res.headers.get('Location')
        twitter_stub = 'https://api.twitter.com/oauth/authorize?oauth_token='
        self.assertTrue(location.startswith(twitter_stub))
    
    def test_invalid_consumer_settings(self):
        """A request to authorize will redirect to failed if the consumer
          settings are invalid.
        """
        
        settings = self.config.registry.settings
        settings['twitterauth.oauth_consumer_key'] = 'blah'
        settings['twitterauth.oauth_consumer_secret'] = 'wrong'
        res = self.app.post('/oauth/twitter/authorize', status=302)
        location = res.headers.get('Location')
        self.assertTrue(location=='http://localhost/oauth/twitter/failed')
    
    def test_authorize_with_twitter_redirects_to_callback(self):
        """After a user authorizes with Twitter, they're redirected to the
          authorize_callback view.
        """
        
        import urllib, urllib2
        
        # Get the auth url to redirect to.
        res = self.app.get('/oauth/twitter/authorize', status=302)
        
        # Redirect and parse the response.
        sock = urllib2.urlopen(res.location)
        res = TestResponse()
        res.body = sock.read()
        sock.close()
        
        # Authenticate with our dummy username and password.
        res.form.set('session[username_or_email]', 'pyramid_twauth')
        res.form.set('session[password]', 'pyramid_twitterauth')
        
        # Submit the form and get the new redirect response.
        data = urllib.urlencode(res.form.submit_fields())
        sock = urllib2.urlopen(res.form.action, data)
        text = sock.read()
        sock.close()
        
        # Manually parse the redirect url out of the meta tag.
        l = len('<meta http-equiv="refresh" content="0;url=')
        pos = text.index('<meta http-equiv="refresh" content="0;url=')
        frag = text[pos+l:]
        pos = frag.index('">')
        url = frag[:pos]
        
        # Test that the fragment starts with our callback url.
        stub = 'http://localhost/oauth/twitter/authorize_callback'
        self.assertTrue(url.startswith(stub))
    

