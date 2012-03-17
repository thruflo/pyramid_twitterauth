# -*- coding: utf-8 -*-

from .hooks import get_twitter
from .tree import Root

def includeme(config):
    """Allow developers to use ``config.include('pyramid_twitterauth')``.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {}
      
      Adds ``twitter`` property to the ``request``::
      
          >>> includeme(mock_config)
          >>> args = (get_twitter, 'twitter')
          >>> mock_config.set_request_property.assert_any_call(*args, reify=True)
      
      Exposes the authentication views::
      
          >>> args = ('twitterauth', '/oauth/twitter/*traverse')
          >>> mock_config.add_route.assert_called_with(*args, factory=Root)
      
    """
    
    # Add ``is_authenticated`` and ``user`` properties to the request.
    settings = config.registry.settings
    config.set_request_property(get_twitter, 'twitter', reify=True)
    
    # Expose the authentication views.
    prefix = settings.get('twitterauth.url_prefix', '/oauth/twitter')
    path = '{0}/*traverse'.format(prefix)
    config.add_route('twitterauth', path, factory=Root)

