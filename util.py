# -*- coding: utf-8 -*-


try:
    from json import dumps as json_dumps, loads as json_loads
except ImportError:
    try:
        from simplejson import dumps as json_dumps, loads as json_loads
    except ImportError:
           raise ImportError("Requires Python 2.6 or simplejson.")


class cache_property(object):
    def __init__(self, func, doc=None):
        self._func = func
        self.__doc__ = doc or func.__doc__
        self.__name__ = func.__name__
        self.__module__ = func.__module__

    def __get__(self, obj, cls=None):
        if obj is None:
            return self
        obj.__dict__[self.__name__] = result = self._func(obj)
        return result

    def __delete__(self, obj):
        if self.__name__ in obj.__dict__:
            del obj.__dict__[self.__name__]

def __immutable(self, *args, **kws):
    raise TypeError('object is immutable')

def as_immutable(coll):
        coll.__delitem__ = __immutable
        coll.__setitem__ = __immutable
        coll.__delitem__ = __immutable
        coll.clear       = __immutable
        coll.update      = __immutable
        coll.setdefault  = __immutable
        coll.pop         = __immutable
        coll.popitem     = __immutable

def to_json(data):
    return json_dumps(data)

def un_json(json):
    return json_loads(json)

def is_collection(data):
    try:
        from collections import Iterable
        return isinstance(data, collections.Iterable)
    except ImportError:
        return hasattr(data, '__contains__')
    except TypeError:
        return False

def is_callable(method):
    try:
        return callable(method)
    except Exception:
        return hasattr(obj, '__call__')

def html_escape(string):
    return string.replace('&','&amp;').replace('<','&lt;').replace('>','&gt;')\
                 .replace('"','&quot;').replace("'",'&#039;')
