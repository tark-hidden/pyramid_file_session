# encoding: utf-8

from pyramid.interfaces import ISession
from pyramid.compat import PY3, pickle
from pyramid.session import manage_accessed, manage_changed
from zope.interface import implementer
from hashlib import md5
import time
import os
import re


def FileSessionFactory(
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
        ):

    @implementer(ISession)
    class FileSession(dict):
        """ Dictionary-like session object, based on CookieSession """

        # configuration parameters
        _directory = directory
        _cookie_name = cookie_name
        _cookie_max_age = max_age
        _cookie_path = path
        _cookie_domain = domain
        _cookie_secure = secure
        _cookie_httponly = httponly
        _cookie_on_exception = set_on_exception
        _timeout = timeout
        _reissue_time = reissue_time

        # dirty flag
        _dirty = False

        def __init__(self, request):
            self.request = request
            now = time.time()
            created = renewed = now
            new = True
            value = None
            state = {}
            cookieval = self._get_cookie()
            if cookieval:
                fname = os.path.join(self._directory, cookieval)
                if os.path.exists(fname):
                    try:
                        with open(fname, 'rb') as f:
                            value = pickle.load(f)
                    except ValueError:
                        value = None

            if value is not None:
                try:
                    rval, cval, sval = value
                    renewed = float(rval)
                    created = float(cval)
                    state = sval
                    new = False
                except (TypeError, ValueError):
                    # value failed to unpack properly or renewed was not
                    # a numeric type so we'll fail deserialization here
                    state = {}

            if self._timeout is not None:
                if now - renewed > self._timeout:
                    # expire the session because it was not renewed
                    # before the timeout threshold
                    state = {}

            self.created = created
            self.accessed = renewed
            self.renewed = renewed
            self.new = new
            dict.__init__(self, state)

        # ISession methods
        def changed(self):
            if not self._dirty:
                self._dirty = True

                def set_cookie_callback(request, response):
                    self._set_cookie(response)
                    self.request = None  # explicitly break cycle for gc
                self.request.add_response_callback(set_cookie_callback)

        def invalidate(self):
            self.clear()  # XXX probably needs to unset cookie

        # non-modifying dictionary methods
        get = manage_accessed(dict.get)
        __getitem__ = manage_accessed(dict.__getitem__)
        items = manage_accessed(dict.items)
        values = manage_accessed(dict.values)
        keys = manage_accessed(dict.keys)
        __contains__ = manage_accessed(dict.__contains__)
        __len__ = manage_accessed(dict.__len__)
        __iter__ = manage_accessed(dict.__iter__)

        if not PY3:
            iteritems = manage_accessed(dict.iteritems)
            itervalues = manage_accessed(dict.itervalues)
            iterkeys = manage_accessed(dict.iterkeys)
            has_key = manage_accessed(dict.has_key)

        # modifying dictionary methods
        clear = manage_changed(dict.clear)
        update = manage_changed(dict.update)
        setdefault = manage_changed(dict.setdefault)
        pop = manage_changed(dict.pop)
        popitem = manage_changed(dict.popitem)
        __setitem__ = manage_changed(dict.__setitem__)
        __delitem__ = manage_changed(dict.__delitem__)

        # flash API methods
        @manage_changed
        def flash(self, msg, queue='', allow_duplicate=True):
            storage = self.setdefault('_f_' + queue, [])
            if allow_duplicate or (msg not in storage):
                storage.append(msg)

        @manage_changed
        def pop_flash(self, queue=''):
            storage = self.pop('_f_' + queue, [])
            return storage

        @manage_accessed
        def peek_flash(self, queue=''):
            storage = self.get('_f_' + queue, [])
            return storage

        # CSRF API methods
        @manage_changed
        def new_csrf_token(self):
            token = self._get_random()
            self['_csrft_'] = token
            return token

        @manage_accessed
        def get_csrf_token(self):
            token = self.get('_csrft_', None)
            if token is None:
                token = self.new_csrf_token()
            return token

        # non-API methods
        def _get_random(self):
            return md5(os.urandom(32)).hexdigest()

        def _get_cookie(self):  # cookie value, not file value itself
            value = self.request.cookies.get(self._cookie_name, '')
            value = re.sub('[^a-f0-9]', '', value)
            return value

        def _set_cookie(self, response):
            if not self._cookie_on_exception:
                exception = getattr(self.request, 'exception', None)
                if exception is not None:  # dont set a cookie during exceptions
                    return False

            cookieval = self.new and self._get_random() or self._get_cookie()
            if not cookieval:
                return False

            value = (self.accessed, self.created, dict(self))
            fname = os.path.join(self._directory, cookieval)
            with open(fname, 'wb') as f:
                pickle.dump(value, f, pickle.HIGHEST_PROTOCOL)

            response.set_cookie(
                self._cookie_name,
                value=cookieval,
                max_age=self._cookie_max_age,
                path=self._cookie_path,
                domain=self._cookie_domain,
                secure=self._cookie_secure,
                httponly=self._cookie_httponly,
                )
            return True

    return FileSession
