# encoding: utf-8

import unittest
from pyramid import testing
from pyramid_file_session import pickle


directory = '/tmp'


class Serializer(object):    
    def _serialize(self, value):
        import os
        import hashlib

        cookieval = hashlib.md5(os.urandom(32)).hexdigest()
        fname = os.path.join(directory, cookieval)
        with open(fname, 'wb') as f:
            pickle.dump(value, f, pickle.HIGHEST_PROTOCOL)
        return cookieval


class CookieSessionTests(Serializer):
    def test_ctor_no_cookie(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        self.assertEqual(dict(session), {})

    def test_instance_conforms(self):
        from zope.interface.verify import verifyObject
        from pyramid.interfaces import ISession
        request = testing.DummyRequest()
        session = self._makeOne(request)
        verifyObject(ISession, session)

    def test_ctor_with_cookie_still_valid(self):
        import time
        request = testing.DummyRequest()
        cookieval = self._serialize((time.time(), 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request)
        self.assertEqual(dict(session), {'state':1})

    def test_ctor_with_cookie_expired(self):
        request = testing.DummyRequest()
        cookieval = self._serialize((0, 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request)
        self.assertEqual(dict(session), {})

    def test_ctor_with_bad_cookie_cannot_deserialize(self):
        request = testing.DummyRequest()
        request.cookies['session'] = 'abc'
        session = self._makeOne(request)
        self.assertEqual(dict(session), {})

    def test_ctor_with_bad_cookie_not_tuple(self):
        request = testing.DummyRequest()
        cookieval = self._serialize('abc')
        request.cookies['session'] = cookieval
        session = self._makeOne(request)
        self.assertEqual(dict(session), {})

    def test_timeout(self):
        import time
        request = testing.DummyRequest()
        cookieval = self._serialize((time.time() - 5, 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request, timeout=1)
        self.assertEqual(dict(session), {})

    def test_timeout_never(self):
        import time
        request = testing.DummyRequest()
        LONG_TIME = 31536000
        cookieval = self._serialize((time.time() + LONG_TIME, 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request, timeout=None)
        self.assertEqual(dict(session), {'state': 1})

    def test_changed(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        self.assertEqual(session.changed(), None)
        self.assertTrue(session._dirty)

    def test_invalidate(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session['a'] = 1
        self.assertEqual(session.invalidate(), None)
        self.assertFalse('a' in session)

    def test_reissue_triggered(self):
        import time
        request = testing.DummyRequest()
        cookieval = self._serialize((time.time() - 2, 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request)
        self.assertEqual(session['state'], 1)
        self.assertTrue(session._dirty)

    def test__set_cookie_on_exception(self):
        request = testing.DummyRequest()
        request.exception = True
        session = self._makeOne(request)
        session._cookie_on_exception = False
        response = DummyResponse()
        self.assertEqual(session._set_cookie(response), False)

    def test__set_cookie_on_exception_no_request_exception(self):
        import webob
        request = testing.DummyRequest()
        request.exception = None
        session = self._makeOne(request)
        session._cookie_on_exception = False
        response = webob.Response()
        self.assertEqual(session._set_cookie(response), True)
        self.assertEqual(response.headerlist[-1][0], 'Set-Cookie')

    def test__set_cookie_real_webob_response(self):
        import webob
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session['abc'] = 'x'
        response = webob.Response()
        self.assertEqual(session._set_cookie(response), True)
        self.assertEqual(response.headerlist[-1][0], 'Set-Cookie')

    def test__set_cookie_options(self):
        from pyramid.response import Response
        request = testing.DummyRequest()
        request.exception = None
        session = self._makeOne(request,
                                cookie_name='abc',
                                path='/foo',
                                domain='localhost',
                                secure=True,
                                httponly=True,
                                )
        session['abc'] = 'x'
        response = Response()
        self.assertEqual(session._set_cookie(response), True)
        cookieval = response.headerlist[-1][1]
        val, domain, path, secure, httponly = [x.strip() for x in
                                               cookieval.split(';')]
        self.assertTrue(val.startswith('abc='))
        self.assertEqual(domain, 'Domain=localhost')
        self.assertEqual(path, 'Path=/foo')
        self.assertEqual(secure, 'secure')
        self.assertEqual(httponly, 'HttpOnly')

    def test_flash_default(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session.flash('msg1')
        session.flash('msg2')
        self.assertEqual(session['_f_'], ['msg1', 'msg2'])

    def test_flash_allow_duplicate_false(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session.flash('msg1')
        session.flash('msg1', allow_duplicate=False)
        self.assertEqual(session['_f_'], ['msg1'])

    def test_flash_allow_duplicate_true_and_msg_not_in_storage(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session.flash('msg1', allow_duplicate=True)
        self.assertEqual(session['_f_'], ['msg1'])

    def test_flash_allow_duplicate_false_and_msg_not_in_storage(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session.flash('msg1', allow_duplicate=False)
        self.assertEqual(session['_f_'], ['msg1'])

    def test_flash_mixed(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session.flash('warn1', 'warn')
        session.flash('warn2', 'warn')
        session.flash('err1', 'error')
        session.flash('err2', 'error')
        self.assertEqual(session['_f_warn'], ['warn1', 'warn2'])

    def test_pop_flash_default_queue(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        queue = ['one', 'two']
        session['_f_'] = queue
        result = session.pop_flash()
        self.assertEqual(result, queue)
        self.assertEqual(session.get('_f_'), None)

    def test_pop_flash_nodefault_queue(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        queue = ['one', 'two']
        session['_f_error'] = queue
        result = session.pop_flash('error')
        self.assertEqual(result, queue)
        self.assertEqual(session.get('_f_error'), None)

    def test_peek_flash_default_queue(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        queue = ['one', 'two']
        session['_f_'] = queue
        result = session.peek_flash()
        self.assertEqual(result, queue)
        self.assertEqual(session.get('_f_'), queue)

    def test_peek_flash_nodefault_queue(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        queue = ['one', 'two']
        session['_f_error'] = queue
        result = session.peek_flash('error')
        self.assertEqual(result, queue)
        self.assertEqual(session.get('_f_error'), queue)

    def test_new_csrf_token(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        token = session.new_csrf_token()
        self.assertEqual(token, session['_csrft_'])

    def test_get_csrf_token(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session['_csrft_'] = 'token'
        token = session.get_csrf_token()
        self.assertEqual(token, 'token')
        self.assertTrue('_csrft_' in session)

    def test_get_csrf_token_new(self):
        request = testing.DummyRequest()
        session = self._makeOne(request)
        token = session.get_csrf_token()
        self.assertTrue(token)
        self.assertTrue('_csrft_' in session)

    def test_no_set_cookie_with_exception(self):
        import webob
        request = testing.DummyRequest()
        request.exception = True
        session = self._makeOne(request, set_on_exception=False)
        session['a'] = 1
        callbacks = request.response_callbacks
        self.assertEqual(len(callbacks), 1)
        response = webob.Response()
        result = callbacks[0](request, response)
        self.assertEqual(result, None)
        self.assertFalse('Set-Cookie' in dict(response.headerlist))

    def test_set_cookie_with_exception(self):
        import webob
        request = testing.DummyRequest()
        request.exception = True
        session = self._makeOne(request)
        session['a'] = 1
        callbacks = request.response_callbacks
        self.assertEqual(len(callbacks), 1)
        response = webob.Response()
        result = callbacks[0](request, response)
        self.assertEqual(result, None)
        self.assertTrue('Set-Cookie' in dict(response.headerlist))

    def test_cookie_is_set(self):
        import webob
        request = testing.DummyRequest()
        session = self._makeOne(request)
        session['a'] = 1
        callbacks = request.response_callbacks
        self.assertEqual(len(callbacks), 1)
        response = webob.Response()
        result = callbacks[0](request, response)
        self.assertEqual(result, None)
        self.assertTrue('Set-Cookie' in dict(response.headerlist))


class IssueSessionTests(CookieSessionTests, unittest.TestCase):
    def _makeOne(self, request, **kw):
        from pyramid_file_session import FileSessionFactory
        return FileSessionFactory(directory, **kw)(request)

    def test_reissue_not_triggered(self):
        import time
        request = testing.DummyRequest()
        cookieval = self._serialize((time.time(), 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request, reissue_time=1)
        self.assertEqual(session['state'], 1)
        self.assertFalse(session._dirty)

    def test_reissue_never(self):
        request = testing.DummyRequest()
        cookieval = self._serialize((0, 0, {'state': 1}))
        request.cookies['session'] = cookieval
        session = self._makeOne(request, reissue_time=None, timeout=None)
        self.assertEqual(session['state'], 1)
        self.assertFalse(session._dirty)


class TestManageAccessed(unittest.TestCase):
    def _makeOne(self, wrapped):
        from pyramid.session import manage_accessed
        return manage_accessed(wrapped)

    def test_accessed_set(self):
        request = testing.DummyRequest()
        session = DummySessionFactory(request)
        session.renewed = 0
        wrapper = self._makeOne(session.__class__.get)
        wrapper(session, 'a')
        self.assertNotEqual(session.accessed, None)
        self.assertTrue(session._dirty)

    def test_accessed_without_renew(self):
        import time
        request = testing.DummyRequest()
        session = DummySessionFactory(request)
        session._reissue_time = 5
        session.renewed = time.time()
        wrapper = self._makeOne(session.__class__.get)
        wrapper(session, 'a')
        self.assertNotEqual(session.accessed, None)
        self.assertFalse(session._dirty)

    def test_already_dirty(self):
        request = testing.DummyRequest()
        session = DummySessionFactory(request)
        session.renewed = 0
        session._dirty = True
        session['a'] = 1
        wrapper = self._makeOne(session.__class__.get)
        self.assertEqual(wrapper.__doc__, session.get.__doc__)
        result = wrapper(session, 'a')
        self.assertEqual(result, 1)
        callbacks = request.response_callbacks
        if callbacks is not None: self.assertEqual(len(callbacks), 0)


class TestManageChanged(unittest.TestCase):
    def _makeOne(self, wrapped):
        from pyramid.session import manage_changed
        return manage_changed(wrapped)

    def test_it(self):
        request = testing.DummyRequest()
        session = DummySessionFactory(request)
        wrapper = self._makeOne(session.__class__.__setitem__)
        wrapper(session, 'a', 1)
        self.assertNotEqual(session.accessed, None)
        self.assertTrue(session._dirty)


class TestCheck_csrf_token(unittest.TestCase):
    def _callFUT(self, *args, **kwargs):
        from pyramid.session import check_csrf_token
        return check_csrf_token(*args, **kwargs)

    def test_success_token(self):
        request = testing.DummyRequest()
        request.params['csrf_token'] = request.session.get_csrf_token()
        self.assertEqual(self._callFUT(request, token='csrf_token'), True)

    def test_success_header(self):
        request = testing.DummyRequest()
        request.headers['X-CSRF-Token'] = request.session.get_csrf_token()
        self.assertEqual(self._callFUT(request, header='X-CSRF-Token'), True)

    def test_success_default_token(self):
        request = testing.DummyRequest()
        request.params['csrf_token'] = request.session.get_csrf_token()
        self.assertEqual(self._callFUT(request), True)

    def test_success_default_header(self):
        request = testing.DummyRequest()
        request.headers['X-CSRF-Token'] = request.session.get_csrf_token()
        self.assertEqual(self._callFUT(request), True)

    def test_failure_raises(self):
        from pyramid.exceptions import BadCSRFToken
        request = testing.DummyRequest()
        self.assertRaises(BadCSRFToken, self._callFUT, request,
                          'csrf_token')

    def test_failure_no_raises(self):
        request = testing.DummyRequest()
        result = self._callFUT(request, 'csrf_token', raises=False)
        self.assertEqual(result, False)


class DummySessionFactory(dict):
    _dirty = False
    _cookie_name = 'session'
    _cookie_max_age = None
    _cookie_path = '/'
    _cookie_domain = None
    _cookie_secure = False
    _cookie_httponly = False
    _timeout = 1200
    _reissue_time = 0

    def __init__(self, request):
        self.request = request
        dict.__init__(self, {})

    def changed(self):
        self._dirty = True


class DummyResponse(object):
    def __init__(self):
        self.headerlist = []

