# -*- coding: utf-8 -*-

from pyramid.httpexceptions import HTTPForbidden
from pyramid.security import NO_PERMISSION_REQUIRED as PUBLIC

from .hooks import get_twitter
from .view import forbidden_view, oauth_failed_view
from .view import oauth_authenticate_view, oauth_authorize_view
from .view import authenticate_callback_view, authorize_callback_view

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
      
      Exposes the ``twitterauth`` route::
      
          >>> args = ('twitterauth', 'oauth/twitter/*traverse')
          >>> mock_config.add_route.assert_any_call(*args)
      
      Exposes the ``oauth_failed_view``::
      
          >>> kwargs = dict(route_name="twitterauth", name='failed', permission=PUBLIC,
          ...         renderer='pyramid_twitterauth:templates/failed.mako')
          >>> mock_config.add_view.assert_any_call(oauth_failed_view, **kwargs)
      
      If in connect mode, exposes the ``authorize`` views::
      
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {}
          >>> mock_config.registry.settings['twitterauth.mode'] = 'connect'
          >>> includeme(mock_config)
          >>> args = (oauth_authorize_view,)
          >>> kwargs = dict(route_name="twitterauth", name='authorize')
          >>> mock_config.add_view.assert_any_call(*args, **kwargs)
          >>> args = (authorize_callback_view,)
          >>> kwargs = dict(route_name="twitterauth", name='authorize_callback')
          >>> mock_config.add_view.assert_any_call(*args, **kwargs)
      
      But not the ``authenticate`` views::
      
          >>> args = (oauth_authenticate_view,)
          >>> kwargs = dict(route_name="twitterauth", name='authenticate', 
          ...         permission=PUBLIC)
          >>> mock_config.add_view.assert_any_call(*args, **kwargs) # doctest: +ELLIPSIS
          Traceback (most recent call last):
          ...
          AssertionError: ...
      
      Otherwise, exposes the ``authenticate`` views and adds the forbidden view.
      (Note that this may require a call ``config.commit()`` inbetween including
      ``pyramid_simpelauth`` and ``pyramid_twitterauth`` to manually resolve a
      ``pyramid.exceptions.ConfigurationConflictError``)::
      
          >>> mock_config = Mock()
          >>> mock_config.registry.settings = {}
          >>> includeme(mock_config)
          >>> kwargs = dict(context=HTTPForbidden, permission=PUBLIC)
          >>> mock_config.add_view.assert_any_call(forbidden_view, **kwargs)
          >>> args = (oauth_authenticate_view,)
          >>> kwargs = dict(route_name="twitterauth", name='authenticate', 
          ...         permission=PUBLIC)
          >>> mock_config.add_view.assert_any_call(*args, **kwargs)
          >>> args = (authenticate_callback_view,)
          >>> kwargs = dict(route_name="twitterauth",
          ...         name='authenticate_callback', permission=PUBLIC)
          >>> mock_config.add_view.assert_any_call(*args, **kwargs)
      
      And not the ``authorize`` views::
      
          >>> args = (oauth_authorize_view,)
          >>> kwargs = dict(route_name="twitterauth", name='authorize')
          >>> mock_config.add_view.assert_any_call(*args, **kwargs) # doctest: +ELLIPSIS
          Traceback (most recent call last):
          ...
          AssertionError: ...
      
    """
    
    # Add ``is_authenticated`` and ``user`` properties to the request.
    settings = config.registry.settings
    config.set_request_property(get_twitter, 'twitter', reify=True)
    
    # Expose the ``twitterauth`` route.
    prefix = settings.get('twitterauth.url_prefix', 'oauth/twitter')
    config.add_route('twitterauth', '{0}/*traverse'.format(prefix))
    
    # Expose the ``failed`` view.
    config.add_view(oauth_failed_view, route_name="twitterauth", name='failed',
            permission=PUBLIC, renderer='pyramid_twitterauth:templates/failed.mako')
    
    # If we're in connect mode, which means we want to allow existing users to
    # connect their Twitter accounts, expose the ``oauth_authorize`` and 
    # ``authorize_callback`` views.
    if settings.get('twitterauth.mode') == 'connect':
        config.add_view(oauth_authorize_view, route_name="twitterauth", name='authorize')
        config.add_view(authorize_callback_view, route_name="twitterauth",
                name='authorize_callback')
    # Otherwise, expose ``oauth_authenticate`` and ``authenticate_callback`` which
    # allow users to signup and login exclusively through Twitter and expose the
    # ``forbidden_view`` so that unauthenticated users accessing a protected
    # resource are automatically redirected to ``oauth_authenticate``.
    else:
        config.add_view(forbidden_view, context=HTTPForbidden, permission=PUBLIC)
        config.add_view(oauth_authenticate_view, route_name="twitterauth",
                name='authenticate', permission=PUBLIC)
        config.add_view(authenticate_callback_view, route_name="twitterauth",
                name='authenticate_callback', permission=PUBLIC)
    

