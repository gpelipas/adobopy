# -*- coding: utf-8 -*-

import functools, types

import util


def login_check(check_func, failed_func=None):
    """Utility decorator to wrapped a method with login process"""
    if not check_func or not util.is_callable(check_func):
       raise Exception('Developer Error: check_func parameter must point to an existing validation function')

    if not check_func and not util.is_callable(check_func):
       raise Exception('Developer Error: failed_func parameter must point to an existing function')

    def _decorate_func_of(wrapped_func):
        def _wrap_call_with(*a, **ka):
            _auth = check_func(*a, **ka)
            if not _auth:
               if check_func:
                  failed_func(*a, **ka)
               else:
                  raise HttpRequestException("Page you are accessing requires successful Login", status=401)
            return wrapped_func(*a, **ka)

        functools.update_wrapper(_decorate_func_of, wrapped_func, updated=[])
        return __wrap_call_with
    return _decorate_func_of
