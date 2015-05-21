"""
pyramid_file_session
--------------------

As you know, SignedCookieSessionFactory stores a base64-encoded pickled object in a user cookie, which can be insecure in some cases.

With this package your cookie has a md5-like string, that identifies a file which lives in a server's directory (`/tmp` by default) and contains a pickled session object.

To be honest, it is a modified version of pyramid.session.BaseCookieSessionFactory with the same behavior.

Documentation: https://github.com/tark-hidden/pyramid_file_session

Changelog
*********


0.1
---

Initial release. I think it is a final release also. Python3 version is not tested, but it will work properly, I guess.
"""
from setuptools import setup

setup(
    name='pyramid_file_session',
    version='0.1',
    url='https://github.com/tark-hidden/pyramid_file_session',
    license='BSD',
    author='Tark',
    maintainer="Tark",
    author_email='tark.hidden@gmail.com',
    description='File-based session factory for Pyramid framework',
    keywords="pyramid file session factory",
    long_description=__doc__,
    py_modules=['pyramid_file_session'],
    zip_safe=False,
    include_package_data=True,
    platforms='any',
    install_requires=[
        'Pyramid'
    ],
    test_suite="tests",
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Topic :: Internet :: WWW/HTTP :: Dynamic Content',
        'Topic :: Software Development :: Libraries :: Python Modules'
    ]    
)
