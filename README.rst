FileSessionFactory
==================
Translation and bug fix in progress.

As you know, SignedCookieSessionFactory stores a base64-encoded pickled object in a user cookie, which can be insecure in some cases.

With this package your cookie has a md5-like string, that identifies a file which lives in a server's directory (`/tmp` by default) and contains a pickled session object.

To be honest, it is a modified version of pyramid.session.BaseCookieSessionFactory with the same behavior.

Installation
------------

Install the extension with::

    $ pip install pyramid_file_session

or::

    $ easy_install pyramid_file_session


Usage
-----

.. code-block:: python

    FileSessionFactory(
        directory='/tmp',
        cookie_name='session',
        max_age=None,
        path='/',
        domain=None,
        secure=False,
        httponly=False,
        timeout=1200,
        reissue_time=0,
        set_on_exception=True,
    )


Default values are very useful, I swear.

On Windows machines... I think you can use Windows for development, right? But Windows has no `/tmp` directory... What am I talking about..? Aha! You can create directory `tmp` in the highest level where `setup.py` lives and reassign `directory` variable on `tmp` - and it will all be OK.


.. code-block:: python

    # encoding: utf-8

    from pyramid.config import Configurator
    from pyramid_file_session import FileSessionFactory
    ...

    def main(global_config, **settings):
        """ This function returns a Pyramid WSGI application.
        """
        config = Configurator(settings=settings)
        config.set_session_factory(FileSessionFactory())
        ...
        return config.make_wsgi_app()


Important notes
---------------

File-based session manager is not so slow (see pic)
Behavior of the FileSessionFactory is the same as SignedCookieSessionFactory. You need to read the standard documentation about using this session factory and request.session itself.

.. figure:: https://cloud.githubusercontent.com/assets/2255508/7739538/17af96b0-ff6b-11e4-9723-fa98c0acc9ed.png

Testing
-------

`tests.py` is a heavily modified version of pyramid/tests/test_session.py. You have no reason to run these tests: they are passed.

::

    $ python setup.py test


On Windows machine you need to create directory `tmp` and change Serializer class `directory = 'tmp'` and _makeOne method in IssueSessionTests class should return FileSessionFactory('tmp', **kw)(request). Sorry, guys.


Changelog
*********

0.1.1
~~~~~

More accuracy work with files. `with open` instead of `open`.


0.1
~~~

Initial release.

Any help to proving this readme file (and package) would be highly appreciated.
