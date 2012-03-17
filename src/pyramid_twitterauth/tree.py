# -*- coding: utf-8 -*-

"""Provides ``AuthRoot`` traversal root factory."""

import logging
logger = logging.getLogger(__name__)

from pyramid.security import Allow, Authenticated, Everyone

class Root(object):
    """Root object of the twitterauth resource tree.  Has no children, 
      i.e.: raises a KeyError on any traversal::
      
          >>> root = Root(None)
          >>> root['anything']
          Traceback (most recent call last):
          ...
          KeyError: 'anything'
      
    """
    
    __name__ = None
    
    __acl__ = [
        #(Allow, Authenticated, 'logout')
    ]
    
    def __init__(self, request):
        self.request = request
    
    def __getitem__(self, key):
        raise KeyError, key
    

