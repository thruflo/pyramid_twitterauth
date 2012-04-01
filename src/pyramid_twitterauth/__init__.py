# -*- coding: utf-8 -*-

from pyramid.httpexceptions import HTTPForbidden
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC

from .hooks import get_twitter
from .view import forbidden_view

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
      
          >>> args = ('twitterauth', 'oauth/twitter/*traverse')
          >>> mock_config.add_route.assert_called_with(*args)
      
      Scans the package::
      
          >>> mock_config.scan.assert_called_with('pyramid_twitterauth')
      
      If told to ``twitterauth.handle_forbidden`` adds the forbidden view.
      (Note that this may require a call ``config.commit()`` inbetween including
      ``pyramid_simpelauth`` and ``pyramid_twitterauth`` to manually resolve a
      ``pyramid.exceptions.ConfigurationConflictError``)::
      
          >>> mock_config.add_view.called
          False
          >>> mock_config.registry.settings['twitterauth.handle_forbidden'] = True
          >>> includeme(mock_config)
          >>> kwargs = dict(context=HTTPForbidden, permission=PUBLIC)
          >>> mock_config.add_view.assert_called_with(forbidden_view, **kwargs)
      
    """
    
    # Add ``is_authenticated`` and ``user`` properties to the request.
    settings = config.registry.settings
    config.set_request_property(get_twitter, 'twitter', reify=True)
    # Expose the authentication views.
    prefix = settings.get('twitterauth.url_prefix', 'oauth/twitter')
    config.add_route('twitterauth', '{0}/*traverse'.format(prefix))
    # If we want users to signup and login through Twitter, configure the 
    if settings.get('twitterauth.handle_forbidden'):
        config.add_view(forbidden_view, context=HTTPForbidden, permission=PUBLIC)
    # Run a venusian scan to pick up the declarative configuration.
    config.scan('pyramid_twitterauth')
    

