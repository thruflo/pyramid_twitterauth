# -*- coding: utf-8 -*-

"""Provides ``TwitterRequestAPI`` class and a ``get_twitter()`` function to get
  an instance of it from the current ``request``.
"""

import tweepy

def get_handler(request, callback=None, Handler=tweepy.OAuthHandler):
    """Convienience function to get an appropriately configured ``Handler``
      instance from the current request.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_request = Mock()
          >>> mock_request.route_url.return_value = 'callback'
          >>> mock_request.registry.settings = {
          ...     'twitterauth.oauth_consumer_key': 'key',
          ...     'twitterauth.oauth_consumer_secret': 'secret'
          ... }
          >>> mock_handler_cls = Mock()
          >>> mock_handler_cls.return_value = 'configured handler'
      
      Returns a ``Handler`` initialised with the consumer settings and the
      callback url::
      
          >>> get_handler(mock_request, Handler=mock_handler_cls)
          'configured handler'
          >>> args = ('key', 'secret')
          >>> kwargs = {'callback': None, 'secure': True}
          >>> mock_handler_cls.assert_called_with(*args, **kwargs)
      
      Constructing the callback url from the ``twitterauth`` route::
      
          >>> get_handler(mock_request, callback='callback', Handler=mock_handler_cls)
          'configured handler'
          >>> mock_request.route_url.assert_called_with('twitterauth', 
          ...         traverse=('callback',))
      
    """
    
    # Get the Twitter app consumer settings.
    settings = request.registry.settings
    key = settings.get('twitterauth.oauth_consumer_key')
    secret = settings.get('twitterauth.oauth_consumer_secret')
    # Construct the callback url for the oauth dance.
    if callback:
        callback = request.route_url('twitterauth', traverse=(callback,))
    # Return the configured handler.
    return Handler(key, secret, callback=callback, secure=True)


class TwitterRequestAPI(object):
    """Adapts a ``request`` to provide an authenticated Twitter api client
      and information on the Twitter api access level we have for that request's
      authenticated user.
    """
    
    client = None
    access_permission = ''
    
    @property
    def has_read_access(self):
        """Do we have read access to the Twitter api for ``self.user``?
          
          Setup::
          
              >>> from mock import Mock
              >>> mock_request = Mock()
              >>> mock_request.user = None
          
          If ``self.access_permission`` contains 'read', returns ``True``::
          
              >>> twitter = TwitterRequestAPI(mock_request)
              >>> twitter.access_permission = 'read'
              >>> twitter.has_read_access
              True
          
          Else returns ``False``::
          
              >>> twitter.access_permission = 'Flobble'
              >>> twitter.has_write_access
              False
          
        """
        
        return 'read' in self.access_permission
    
    @property
    def has_write_access(self):
        """Do we have write access to the Twitter api for ``self.user``?
          
          Setup::
          
              >>> from mock import Mock
              >>> mock_request = Mock()
              >>> mock_request.user = None
          
          If ``self.access_permission`` contains 'write', returns ``True``::
          
              >>> twitter = TwitterRequestAPI(mock_request)
              >>> twitter.access_permission = 'read-write'
              >>> twitter.has_write_access
              True
          
          Else returns ``False``::
          
              >>> twitter.access_permission = 'Flobble'
              >>> twitter.has_write_access
              False
          
        """
        
        return 'write' in self.access_permission
    
    
    def __init__(self, request, handler_factory=get_handler, Api=tweepy.API):
        """Initialise an OAuth handler with the right consumer settings, then
          if the user has a twitter account setup the twitter api client and
          set the access permission.
          
          Setup::
          
              >>> from mock import Mock
              >>> mock_request = Mock()
              >>> mock_user = Mock()
          
          If there isn't an authenticated user, no dice::
          
              >>> mock_request.user = None
              >>> twitter = TwitterRequestAPI(mock_request)
              >>> twitter.client
              >>> twitter.has_read_access
              False
          
          Ditto a user without a Twitter account::
          
              >>> mock_user.twitter_account = None
              >>> mock_request.user = mock_user
              >>> twitter = TwitterRequestAPI(mock_request)
              >>> twitter.client
              >>> twitter.has_read_access
              False
          
          More setup::
          
              >>> mock_twitter_account = Mock()
              >>> mock_twitter_account.oauth_token = 'token'
              >>> mock_twitter_account.oauth_token_secret = 'token secret'
              >>> mock_twitter_account.access_permission = 'read'
              >>> mock_handler = Mock()
              >>> mock_handler_factory = Mock()
              >>> mock_handler_factory.return_value = mock_handler
              >>> mock_api_factory = Mock()
              >>> mock_api_factory.return_value = '<api client>'
          
          If we do have an authenticated user with a Twitter account, then we
          authenticate the oauth handler::
          
              >>> mock_user.twitter_account = mock_twitter_account
              >>> twitter = TwitterRequestAPI(mock_request, 
              ...                             handler_factory=mock_handler_factory, 
              ...                             Api=mock_api_factory)
              >>> mock_handler_factory.assert_called_with(mock_request)
              >>> mock_handler.set_access_token.assert_called_with('token', 
              ...                                                  'token secret')
              >>> mock_api_factory.assert_called_with(mock_handler)
              >>> twitter.client
              '<api client>'
              >>> twitter.has_read_access
              True
          
        """
        
        # Initialise an OAuth handler with the right consumer settings.
        oauth_handler = handler_factory(request)
        # If the user has a twitter account.
        if request.user and hasattr(request.user, 'twitter_account'):
            twitter_account = request.user.twitter_account
            if twitter_account:
                # Authenticate the handler with the user's access token details.
                oauth_token = twitter_account.oauth_token
                oauth_token_secret = twitter_account.oauth_token_secret
                oauth_handler.set_access_token(oauth_token, oauth_token_secret)
                # Setup the twitter api client
                self.client = Api(oauth_handler)
                # Set the access permission
                self.access_permission = twitter_account.access_permission
    


# Reified as the ``request.twitter`` property.
def get_twitter(request, cls=TwitterRequestAPI):
    """Return a ``cls`` instance instantiated with ``request``::
      
          >>> from mock import Mock
          >>> mock_cls = Mock()
          >>> mock_cls.return_value = '<twitter instance>'
          >>> mock_request = Mock()
          >>> get_twitter(mock_request, cls=mock_cls)
          '<twitter instance>'
          >>> mock_cls.assert_called_with(mock_request)
      
    """
    
    return cls(request)

