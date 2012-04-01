[pyramid_twitterauth][] is a package that extends [pyramid_simpleauth][] to
allow a [Pyramid][] application's users to authenticate via Twitter and / or
connect their Twitter account.

Once they've done so, you get an authenticated [Tweepy][] client as 
`request.twitter.client` and flags for `has_read_access` & `has_write_access`::

    # e.g.: in a view callable
    if request.twitter.has_write_access:
        request.twitter.client.update_status('OMG #lolcats')

# Install

Install the package as you would any other Python egg, e.g.:

    easy_install pyramid_twitterauth

Then include it along with a session factory, `pyramid_tm`, `pyramid_basemodel`
and `pyramid_simpleauth` in the configuration portion of your Pyramid app:

    # Configure a session factory, here, we're using `pyramid_beaker`.
    config.include('pyramid_beaker')
    config.set_session_factory(session_factory_from_settings(settings))
    
    # Include the packages.  The order is significant if you want 
    # `pyramid_basemodel` to "just work".
    config.include('pyramid_simpleauth')
    config.include('pyramid_twitterauth')
    config.include('pyramid_basemodel')
    
    # Either include `pyramid_tm` or deal with committing transactions yourself.
    config.include('pyramid_tm')

Note that you must provide an `sqlalchemy.url` in your `.ini` settings, or bind
the SQLAlchemy models and scoped `Session` to a database engine yourself.

# Mode

In default mode, the package allows users to authenticate via Twitter.  This is
done by exposing the following views::

* /oauth/twitter/authenticate
* /oauth/twitter/authenticate_callback
* /oauth/twitter/failed
* an HTTPForbidden view that redirects to /oauth/twitter/authenticate

In "connect" mode, the package allows *existing* authenticated users to connect
their Twitter accounts.  This is done by exposing views at::

* /oauth/twitter/authorize
* /oauth/twitter/authorize_callback

These two modes are currently mutually exclusive.  To enable "connect" mode,
set ``twitterauth.mode`` in your `.ini` settings::

    twitterauth.mode = connect

# Settings

Specify your Twitter app's OAuth consumer info in your ::

    twitterauth.oauth_consumer_key = <key>
    twitterauth.oauth_consumer_secret = <secret>

Views are exposed by default at `/oauth/twitter/...`.  To use a different path:

    twitterauth.url_prefix = 'somewhere'

# Tests

I've only tested the package under Python 2.6 and 2.7 atm.  You'll need `nose`, 
`coverage`, `mock` and `WebTest`.  Then, e.g.:

    $ nosetests --cover-package=pyramid_twitterauth --cover-tests --with-doctest --with-coverage pyramid_twitterauth
    ......................................
    Name                        Stmts   Miss  Cover   Missing
    ---------------------------------------------------------
    pyramid_twitterauth            18      0   100%   
    pyramid_twitterauth.hooks      28      0   100%   
    pyramid_twitterauth.model      21      0   100%   
    pyramid_twitterauth.tests     370      0   100%   
    pyramid_twitterauth.view      157      0   100%   
    ---------------------------------------------------------
    TOTAL                         594      0   100%   
    ----------------------------------------------------------------------
    Ran 45 tests in 9.090s

    OK

[pyramid]: http://docs.pylonsproject.org/projects/pyramid/en/latest
[pyramid_simpleauth]: http://github.com/thruflo/pyramid_simpleauth
[pyramid_twitterauth]: http://github.com/thruflo/pyramid_twitterauth
[tweepy]: https://github.com/tweepy/tweepy
