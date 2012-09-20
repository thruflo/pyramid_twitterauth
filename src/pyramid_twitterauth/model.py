# -*- coding: utf-8 -*-

"""Provides an SQLAlchemy based ``TwitterAccount`` model class."""

import json

from sqlalchemy import Column, ForeignKey
from sqlalchemy import BigInteger, Integer, Unicode, UnicodeText
from sqlalchemy.orm import backref, relationship

from zope.interface import implements

from pyramid_basemodel import Base, BaseMixin, Session, save
from pyramid_simpleauth import model as simpleauth_model

_user_backref = backref("twitter_account", lazy="joined", uselist=False)
_account_backref = backref("profile", uselist=False)

from .interfaces import ITwitterAccount

class TwitterAccount(Base, BaseMixin):
    """A user's twitter account with oauth token and access permission data."""
    
    implements(ITwitterAccount)
    
    __tablename__ = 'auth_twitter_accounts'
    
    twitter_id = Column(BigInteger, unique=True)
    screen_name = Column(Unicode(20))
    
    oauth_token = Column(Unicode(200))
    oauth_token_secret = Column(Unicode(200))
    access_permission = Column(Unicode(64))
    
    # XXX defines a relation to a table defined in `pyramid_simpleauth`.
    user_id = Column(Integer, ForeignKey('auth_users.id'))
    user = relationship(simpleauth_model.User, lazy='joined', backref=_user_backref)
    
    def __json__(self):
        """Return a dictionary representation of the ``TwitterAccount`` instance.
          
              >>> account = TwitterAccount(twitter_id=1234, screen_name='thruflo')
              >>> account.__json__()
              {'twitter_id': 1234, 'screen_name': 'thruflo'}
          
        """
        
        data = {'twitter_id': self.twitter_id, 'screen_name': self.screen_name}
        if self.profile:
            data.update(self.profile.data)
        return data
    

class TwitterProfile(Base, BaseMixin):
    """Stores a user's twitter profile data as a string."""
    
    __tablename__ = 'auth_twitter_profiles'
    
    id = Column(BigInteger, ForeignKey('auth_twitter_accounts.twitter_id'),
            primary_key=True)
    twitter_account = relationship(TwitterAccount, backref=_account_backref)
    
    @property
    def data(self):
        return json.loads(self.data_str)
    
    data_str = Column(UnicodeText)
    
    def set_data_from_tweepy_user(self, user):
        data = user.__getstate__()
        if 'status' in data:
            del data['status']
        if 'created_at' in data:
            data['created_at'] = data['created_at'].isoformat()
        self.data_str = json.dumps(data)
    
    @classmethod
    def create_from_tweepy_user(cls, user):
        profile = TwitterProfile()
        profile.id = user.id
        profile.set_data_from_tweepy_user(user)
        return profile
    


def get_existing_twitter_account(twitter_id, cls=TwitterAccount):
    """Get an existing twitter account from the ``twitter_id`` provided.
      
      Setup::
      
          >>> from mock import Mock
          >>> mock_cls = Mock()
          >>> mock_filtered_query = Mock()
          >>> mock_filtered_query.first.return_value = 'twitter user 1'
          >>> mock_cls.query.filter_by.return_value = mock_filtered_query
      
      Queries using the ``twitter_id`` and returns the first result::
      
          >>> get_existing_twitter_account(1, cls=mock_cls)
          'twitter user 1'
          >>> mock_cls.query.filter_by.assert_called_with(twitter_id=1)
      
    """
    
    query = cls.query.filter_by(twitter_id=twitter_id)
    return query.first()

