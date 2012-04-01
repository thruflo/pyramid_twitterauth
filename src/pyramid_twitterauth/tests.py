# -*- coding: utf-8 -*-

"""Integration and functional tests for ``pyramid_twitterauth``."""

import unittest

try: # pragma: no cover
    from webtest import TestApp, TestRequest, TestResponse
except ImportError: # pragma: no cover
    pass

def config_factory(**settings):
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
    # Initialise the ``Configurator`` and setup a session factory.
    config = Configurator(settings=settings)
    config.set_session_factory(UnencryptedCookieSessionFactoryConfig('psst'))
    # Include the dependencies.
    config.include('pyramid_tm')
    config.include('pyramid_simpleauth')
    config.include('pyramid_twitterauth')
    config.include('pyramid_basemodel')
    # Return the configurator instance.
    return config


class TestCallbackView(unittest.TestCase):
    """Integration tests for the (lengthy) OAuth callback view."""
    
    def setUp(self):
        """Bind model to an in memory db and setup a mock request."""
        
        from mock import Mock
        from sqlalchemy import engine_from_config
        from pyramid_basemodel import bind_engine
        from pyramid_twitterauth import view
        # Bind the engine to an in memory db just in case.
        key = 'xZNXRgs8oqEcHOBxf4vpw'
        secret = 'E9G2yBiyvp16rZ9hh3QhOe5MXU1Ecwo2LIYEbLbHdto'
        settings = {
            'sqlalchemy.url': 'sqlite:///:memory:',
        #    'twitterauth.oauth_consumer_key': key,
        #    'twitterauth.oauth_consumer_secret': secret
        }
        engine = engine_from_config(settings, 'sqlalchemy.')
        bind_engine(engine, should_drop=True)
        # Setup a mock request.
        mock_request = Mock()
        mock_request.config.registry.settings = settings
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
        # Patch module.
        self._get_existing_twitter_account = view.get_existing_twitter_account
        self._remember = view.remember
        self._save = view.simpleauth_model.save
        self._TwitterAccount = view.TwitterAccount
        view.get_existing_twitter_account = Mock()
        view.remember = Mock()
        view.remember.return_value = {}
        view.simpleauth_model.save = Mock()
        view.TwitterAccount = Mock()
    
    def tearDown(self):
        """Make sure the session is cleared between tests and restore module
          defaults.
        """
        
        from pyramid_basemodel import Session
        from pyramid_twitterauth import view
        
        # Clear session.
        Session.remove()
        # Restore module.
        view.get_existing_twitter_account = self._get_existing_twitter_account
        view.remember = self._remember
        view.simpleauth_model.save = self._save
        view.TwitterAccount = self._TwitterAccount
    
    def makeOne(self, *args, **kwargs):
        """Call the OAuth callback view and return the response."""
        
        from pyramid_twitterauth.view import oauth_callback_view
        return oauth_callback_view(*args, **kwargs)
    
    def test_denied_signup(self):
        """If the user denied our app and this is a signup then returns an
          ``HTTPUnauthorized``.
        """
        
        from pyramid.httpexceptions import HTTPUnauthorized
        
        self.request.GET['denied'] = 'abcd'
        self.request.session['twitter_oauth_is_signin'] = True
        response = self.makeOne(self.request)
        self.assertTrue(isinstance(response, HTTPUnauthorized))
    
    def test_denied_not_signup(self):
        """If the user denied our app and this is not a signup then returns an
          ``HTTPForbidden``.
        """
        
        from pyramid.httpexceptions import HTTPForbidden
        
        self.request.GET['denied'] = 'abcd'
        self.request.session['twitter_oauth_is_signin'] = False
        response = self.makeOne(self.request)
        self.assertTrue(isinstance(response, HTTPForbidden))
    
    def test_convert_to_access_token_fails(self):
        """If our call to the Twitter API to convert our stored request token into
          an access token fails (for example, because Twitter is over capacity),
          redirects to the failed view.
        """
        
        import tweepy
        from mock import Mock
        from pyramid.httpexceptions import HTTPFound
        
        def raise_tweepy_error(*args, **kwargs):
            raise tweepy.TweepError('a')
        
        mock_handler_factory = Mock()
        mock_handler = Mock()
        mock_handler.get_access_token = raise_tweepy_error
        mock_handler_factory.return_value = mock_handler
        response = self.makeOne(self.request, handler_factory=mock_handler_factory)
        self.assertTrue(isinstance(response, HTTPFound))
        self.request.route_url.assert_called_with('twitterauth', traverse=('failed',))
    
    def test_verify_credentials_fails(self):
        """If our call to the Twitter API to verify the user's credentials (and thus
          find out who they are) fails, redirects to the failed view.
        """
        
        import tweepy
        from mock import Mock
        from pyramid.httpexceptions import HTTPFound
        
        def raise_tweepy_error(*args, **kwargs):
            raise tweepy.TweepError('a')
        
        mock_handler_factory = Mock()
        mock_api_factory = Mock()
        mock_client = Mock()
        mock_client.verify_credentials = raise_tweepy_error
        mock_api_factory.return_value = mock_client
        response = self.makeOne(self.request, handler_factory=mock_handler_factory,
                                Api=mock_api_factory)
        self.assertTrue(isinstance(response, HTTPFound))
        mock_api_factory.assert_called_with(mock_handler_factory.return_value)
        self.request.route_url.assert_called_with('twitterauth', traverse=('failed',))
    
    def test_verify_credentials_false_signup(self):
        """If the user's credentials are not verified and this is a signup,
          returns ``HTTPUnauthorized``.
        """
        
        import tweepy
        from mock import Mock
        from pyramid.httpexceptions import HTTPUnauthorized
        
        mock_handler_factory = Mock()
        mock_api_factory = Mock()
        mock_client = Mock()
        mock_client.verify_credentials.return_value = False
        mock_api_factory.return_value = mock_client
        
        # When a signin, returns HTTPUnauthorized
        self.request.session['twitter_oauth_is_signin'] = True
        response = self.makeOne(self.request, handler_factory=mock_handler_factory,
                                Api=mock_api_factory)
        self.assertTrue(isinstance(response, HTTPUnauthorized))
    
    def test_verify_credentials_false_not_signup(self):
        """If the user's credentials are not verified and this is not a signup,
          returns ``HTTPForbidden``.
        """
        
        import tweepy
        from mock import Mock
        from pyramid.httpexceptions import HTTPForbidden
        
        mock_handler_factory = Mock()
        mock_api_factory = Mock()
        mock_client = Mock()
        mock_client.verify_credentials.return_value = False
        mock_api_factory.return_value = mock_client
        
        # When not a signin, returns HTTPForbidden
        self.request.session['twitter_oauth_is_signin'] = False
        response = self.makeOne(self.request, handler_factory=mock_handler_factory,
                                Api=mock_api_factory)
        self.assertTrue(isinstance(response, HTTPForbidden))
        
    
    def test_update_existing_authenticated_users_access_token(self):
        """If we have an authenticated user with a twitter account, their access
          token is updated.
        """
        
        from mock import Mock
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        view.get_existing_twitter_account.return_value = mock_twitter_account
        self.request.user = Mock()
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        # The ``twitter_account`` has had it's access details updated.
        self.assertTrue(mock_twitter_account.oauth_token == 'key')
        self.assertTrue(mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(mock_twitter_account.access_permission == 'read')
        # And the request.user set as it's user.
        self.assertTrue(mock_twitter_account.user == self.request.user)
        # And was passed to model.save.
        view.simpleauth_model.save.assert_called_with(mock_twitter_account)
    
    def test_add_twitter_account_to_authenticated_user(self):
        """If we have an authenticated user without a twitter account, we create
          a twitter account for them.
        """
        
        from mock import Mock
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        view.TwitterAccount.return_value = mock_twitter_account
        view.get_existing_twitter_account.return_value = None
        mock_twitter_user = Mock()
        mock_twitter_user.id = 1234
        mock_twitter_user.screen_name = 'thruflo'
        self.mock_client.verify_credentials.return_value = mock_twitter_user
        self.request.user = Mock()
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        # The ``twitter_account`` has been created and had it's access details set.
        self.assertTrue(view.TwitterAccount.called)
        self.assertTrue(mock_twitter_account.twitter_id == 1234)
        self.assertTrue(mock_twitter_account.screen_name == 'thruflo')
        self.assertTrue(mock_twitter_account.oauth_token == 'key')
        self.assertTrue(mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(mock_twitter_account.access_permission == 'read')
        # And the request.user set as it's user.
        self.assertTrue(mock_twitter_account.user == self.request.user)
        # And was passed to model.save.
        view.simpleauth_model.save.assert_called_with(mock_twitter_account)
    
    def test_log_in_existing_user(self):
        """If we don't have an authenticated user but the twitter user matches
          an existing twitter account which is related to a user, that user is
          logged in.
        """
        
        from mock import Mock
        from pyramid_twitterauth import view
        mock_user = Mock()
        mock_twitter_account = Mock()
        mock_twitter_account.twitter_id = 1234
        mock_twitter_account.user = mock_user
        view.get_existing_twitter_account.return_value = mock_twitter_account
        mock_twitter_user = Mock()
        mock_twitter_user.id = 1234
        self.mock_client.verify_credentials.return_value = mock_twitter_user
        self.request.user = None
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        # The ``twitter_account`` had it's access details set.
        self.assertTrue(mock_twitter_account.oauth_token == 'key')
        self.assertTrue(mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(mock_twitter_account.access_permission == 'read')
        # And was passed to model.save.
        view.simpleauth_model.save.assert_called_with(mock_twitter_account)
        # And the existing ``twitter_account.user`` has been logged in.
        view.remember.assert_called_with(self.request, mock_user.canonical_id)
    
    def test_create_new_user_signin(self):
        """If we don't have an authenticated user and the twitter user doesn't
          match an existing twitter account, create a twitter account and a user.
        """
        
        from mock import Mock
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        mock_twitter_account.user = None
        view.TwitterAccount.return_value = mock_twitter_account
        view.get_existing_twitter_account.return_value = None
        mock_twitter_user = Mock()
        mock_twitter_user.id = 1234
        mock_twitter_user.screen_name = 'thruflo'
        self.mock_client.verify_credentials.return_value = mock_twitter_user
        self.request.user = None
        self.request.session['twitter_oauth_is_signin'] = True
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        # The ``twitter_account`` has been created and had it's access details set.
        self.assertTrue(view.TwitterAccount.called)
        self.assertTrue(mock_twitter_account.twitter_id == 1234)
        self.assertTrue(mock_twitter_account.screen_name == 'thruflo')
        self.assertTrue(mock_twitter_account.oauth_token == 'key')
        self.assertTrue(mock_twitter_account.oauth_token_secret == 'secret')
        self.assertTrue(mock_twitter_account.access_permission == 'read')
        # Passed to model.save.
        view.simpleauth_model.save.assert_called_with(mock_twitter_account)
        # A new user has been created, related and logged in
        self.assertTrue(isinstance(mock_twitter_account.user, view.simpleauth_model.User))
        self.assertTrue(mock_twitter_account.user.username == u'thruflo')
        view.remember.assert_called_with(self.request, mock_twitter_account.user.canonical_id)
    
    def test_create_new_user_not_signin(self):
        """Creating a new user results in unauthorised if not a signin."""
        
        from mock import Mock
        from pyramid.httpexceptions import HTTPUnauthorized
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        mock_twitter_account.user = None
        view.TwitterAccount.return_value = mock_twitter_account
        view.get_existing_twitter_account.return_value = None
        mock_twitter_user = Mock()
        mock_twitter_user.id = 1234
        mock_twitter_user.screen_name = 'thruflo'
        self.mock_client.verify_credentials.return_value = mock_twitter_user
        self.request.user = None
        self.request.session['twitter_oauth_is_signin'] = False
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        self.assertTrue(isinstance(response, HTTPUnauthorized))
    
    def test_next_param(self):
        """Redirects to ``next``."""
        
        # Patch ``get_existing_twitter_account`` to return a mock ``twitter_account``.
        from mock import Mock
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        view.get_existing_twitter_account.return_value = mock_twitter_account
        
        # Patch ``self.request``.
        self.request.user = Mock()
        self.request.session['twitter_oauth_next_url'] = '/next'
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        self.assertTrue(response.location == '/next')
    
    def test_no_next_no_route(self):
        """Redirects to ``/``."""
        
        # Patch ``get_existing_twitter_account`` to return a mock ``twitter_account``.
        from mock import Mock
        from pyramid_twitterauth import view
        mock_twitter_account = Mock()
        view.get_existing_twitter_account.return_value = mock_twitter_account
        self.request.user = Mock()
        self.request.session['twitter_oauth_next_url'] = None
        def raise_key_error(*args, **kwargs):
            raise KeyError
        
        self.request.route_url = raise_key_error
        response = self.makeOne(self.request, Api=self.mock_api_factory,
                                handler_factory=self.mock_handler_factory)
        self.assertTrue(response.location == '/')
    


class TestAuthRedirects(unittest.TestCase):
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
        """A request to the authorize view should redirect to Twitter."""
        
        res = self.app.post('/oauth/twitter/authorize', status=302)
        location = res.headers.get('Location')
        twitter_stub = 'https://api.twitter.com/oauth/authorize?oauth_token='
        self.assertTrue(location.startswith(twitter_stub))
    
    def test_invalid_consumer_settings(self):
        """A request to authenticate or authorize will redirect to failed if the
          consumer settings are invalid.
        """
        
        settings = self.config.registry.settings
        settings['twitterauth.oauth_consumer_key'] = 'blah'
        settings['twitterauth.oauth_consumer_secret'] = 'wrong'
        res = self.app.post('/oauth/twitter/authenticate', status=302)
        location = res.headers.get('Location')
        self.assertTrue(location=='http://localhost/oauth/twitter/failed')
        res = self.app.post('/oauth/twitter/authorize', status=302)
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
        stub = 'http://localhost/oauth/twitter/callback'
        self.assertTrue(url.startswith(stub))
        
        ## Follow the URL.
        #res = self.app.get(url, status="*")
    

