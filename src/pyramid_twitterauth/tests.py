# -*- coding: utf-8 -*-

"""Functional tests for ``pyramid_twitterauth``."""

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
    config.include('pyramid_basemodel')
    config.include('pyramid_simpleauth')
    # Include simpleauth.
    config.include('pyramid_twitterauth')
    # Return the configurator instance.
    return config


class TestAuthRedirects(unittest.TestCase):
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
        
        # Follow the URL.
        #res = self.app.get(url, status=302)
        
    

