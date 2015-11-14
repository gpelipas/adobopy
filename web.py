# -*- coding: utf-8 -*-

import cgi
import mimetypes
import os
import re
import StringIO
import sys
import traceback
import types
import util

from util import cache_property


HTTP_STATUS_MAP = {
    100: 'CONTINUE',
    101: 'SWITCHING PROTOCOLS',
    200: 'OK',
    201: 'CREATED',
    202: 'ACCEPTED',
    203: 'NON-AUTHORITATIVE INFORMATION',
    204: 'NO CONTENT',
    205: 'RESET CONTENT',
    206: 'PARTIAL CONTENT',
    300: 'MULTIPLE CHOICES',
    301: 'MOVED PERMANENTLY',
    302: 'FOUND',
    303: 'SEE OTHER',
    304: 'NOT MODIFIED',
    305: 'USE PROXY',
    306: 'RESERVED',
    307: 'TEMPORARY REDIRECT',
    400: 'BAD REQUEST',
    401: 'UNAUTHORIZED',
    402: 'PAYMENT REQUIRED',
    403: 'FORBIDDEN',
    404: 'NOT FOUND',
    405: 'METHOD NOT ALLOWED',
    406: 'NOT ACCEPTABLE',
    407: 'PROXY AUTHENTICATION REQUIRED',
    408: 'REQUEST TIMEOUT',
    409: 'CONFLICT',
    410: 'GONE',
    411: 'LENGTH REQUIRED',
    412: 'PRECONDITION FAILED',
    413: 'REQUEST ENTITY TOO LARGE',
    414: 'REQUEST-URI TOO LONG',
    415: 'UNSUPPORTED MEDIA TYPE',
    416: 'REQUESTED RANGE NOT SATISFIABLE',
    417: 'EXPECTATION FAILED',
    500: 'INTERNAL SERVER ERROR',
    501: 'NOT IMPLEMENTED',
    502: 'BAD GATEWAY',
    503: 'SERVICE UNAVAILABLE',
    504: 'GATEWAY TIMEOUT',
    505: 'HTTP VERSION NOT SUPPORTED'
}

log_method_mapping = False

class HttpRequestHandler(object):
      """Main HTTP Request Handler class """
      def __init__(self, app='DEFAULT', debug_enabled = False):
          self.__app = app
          self.debug_enabled = debug_enabled
          self.__map = {
                     'GET': [],
                     'POST': [],
                     'PUT': [],
                     'HEAD': [],
                     'DELETE': []
                     }
          self.__init_log()
          
      def __init_log(self):
        print 'Initializing request method mapping'
    
      def RequestMap(self, url, methods=['GET'], produces='text/html'):
          def __decorate_func_of(func):
              self.__map_request(url, methods, func, produces)
              def __wrap_call_with(*a, **ka):                  
                  return func(*a, **ka)
              return __wrap_call_with
          return __decorate_func_of

      def __map_request(self, url, methods, func_callback, produces='text/html'):
          # TODO: make a dict that uses class+method name as key
          if util.is_callable(func_callback) and not hasattr(func_callback, 'is_web_mapped'):
              regex_obj = re.compile("^%s$" % url)
              for m in methods:
                  if log_method_mapping:  
                    print '  mapping url-path:' + url + ' = ' + func_callback.__name__ + '()'
                  self.__map[m].append((regex_obj, url, func_callback))

              func_callback.is_web_mapped = True
              func_callback.produces = produces


      def __handle_error(self, exception, raw_env_proc):
          env, start_response = raw_env_proc

          err_msg = '<h1>Error occured while processing request: %s</h1>' % (
                    util.html_escape(env.get('PATH_INFO', '/')))

          if self.debug_enabled:
             (e_type, e_value, e_tb) = sys.exc_info()
             err_msg += '<h2>Error:</h2><pre>%s</pre><h2>Traceback:</h2><pre>%s</pre>\n' % (
                        exception,
                        ''.join(traceback.format_exception(e_type, e_value, e_tb))
                        )
             #print exception

          env['wsgi.errors'].write(err_msg)
          headers = [('Content-Type', 'text/html; charset=UTF-8')]

          if isinstance(exception, HttpRequestException):
             status = exception.status
             status_str = "%d %s" % (status, HTTP_STATUS_MAP.get(status))
          else:
             status = 500
             status_str = "%d %s" % (status, HTTP_STATUS_MAP.get(status))
            
          start_response(status_str, headers)
          return [ err_msg ]


      def __find_mapped_func(self, request):
          method_action = request.method
          if not method_action in self.__map:
             raise NotFoundError("The HTTP request method '%s' is not supported." % method_action)

          # TODO: make the url matching fast
          for url_set in self.__map[method_action]:
              match = url_set[0].search(request.path)

              if match is not None:
                 return url_set

          raise NotFoundError("Oopps! page not found.")


      def __call__(self, environ, start_response):
          try:
              # create http request
              request = HttpRequest(environ)

              (re_url, url, func_callback) = self.__find_mapped_func(request)

              resp_mimetype = func_callback.produces
              if "application/json" == resp_mimetype.lower():
                 response = HttpJSonResponse(output = {}, content_type = resp_mimetype)
              else:
                 response = HttpResponse(content_type = resp_mimetype)

              opt_func_out = func_callback(request, response) # call the web-mapped-function
              # developer can directly manipulate the response, or return objects|string as ouput

              if opt_func_out is not None and opt_func_out:
                 if isinstance(opt_func_out, basestring):
                    response.set_output_body( str(opt_func_out) )

                 elif util.is_collection(opt_func_out): # is collection
                    response.set_output_body( util.to_json(str(opt_func_out)) )

              return response.send(start_response)

          except (KeyboardInterrupt, SystemExit, MemoryError):
              raise InternalServerError("Request failed due to an Internal Server Error.")

          except Exception, e:
              return self.__handle_error(e, (environ, start_response))

# Singleton Default 
class DefaultHttpRequestHandler(HttpRequestHandler):
    _instance = None
    _init_done = None
    
    def __init__(self, *a, **ka):        
        if not DefaultHttpRequestHandler._init_done:
            super(DefaultHttpRequestHandler, self).__init__(*a, **ka)
            DefaultHttpRequestHandler._init_done = True
            
        DefaultHttpRequestHandler._instance = self
        
        # re-apply debug flag
        if 'debug_enabled' in ka:
            self.debug_enabled = ka['debug_enabled']
        
    def __new__(cls, *args, **kwargs):
        if not DefaultHttpRequestHandler._instance:
            DefaultHttpRequestHandler._instance = super(DefaultHttpRequestHandler, cls).__new__(cls, *args, **kwargs)
            DefaultHttpRequestHandler._init_done = False
        return DefaultHttpRequestHandler._instance


class HttpRequestException(Exception):
      def __init__(self, message, status=404):
          super(HttpRequestException, self).__init__(message)
          self.__status = status

      def get_status(self):
          return self.__status

      # classic property creation for class.
      status = property(get_status, None, None)


class NotFoundError(HttpRequestException):
      def __init__(self, message):
          super(NotFoundError, self).__init__(message, 404)

class BadRequestError(HttpRequestException):
      def __init__(self, message):
          super(NotFoundError, self).__init__(message, 400)

class ForbiddenError(HttpRequestException):
      def __init__(self, message):
          super(ForbiddenError, self).__init__(message, 403)

class InternalServerError(HttpRequestException):
      def __init__(self, message):
          super(InternalServerError, self).__init__(message, 500)

class HttpResponse(object):
      def __init__(self, output=None, headers=None, status=200, content_type='text/html'):
          self.__status = status
          self.content_type = content_type
          self.__resp_body = output
          self.__headers = []
          
          if headers and isinstance(headers, list):
            self.__headers = headers

      def get_status(self):
          return self.__status

      status = property(get_status, None, None)

      def get_http_status(self):
          return "%d %s" % (self.status, HTTP_STATUS_MAP.get(self.status))

      http_status = property(get_http_status, None, None)

      def set_output_body(self, ouput):
          self.__resp_body = ouput

      def get_output_body(self):
          return self.__resp_body

      output_body = property(get_output_body, set_output_body, None)

      # Add text to response
      def append(self, text):
          self.__resp_body += str(text)
          return self

      # Implement +=
      def __iadd__(self, text):
          return self.append(text)

      def put_header(self, header_key, header_value):
          self.__headers[header_key] = header_value

      def get_headers(self):
          return self.__headers

      def send(self, start_response):
          # set basic response header
          self.__headers += [('Content-Length', str(len(self.__resp_body)))]
          self.__headers += [('Content-Type', "%s; charset=UTF-8" % self.content_type)]

          status_str = self.get_http_status()
          start_response(status_str, self.__headers)
          body = self.__resp_body
          return [ body ]


class HttpJSonResponse(HttpResponse):
      def __init__(self, output, headers=None, status=200, content_type='application/json'):
          super(HttpJSonResponse, self).__init__(output, headers, status, content_type)

      # not supported
      def append(self, data):
          raise TypeError("Not supported in HttpJSonResponse.")

      # not supported
      def __iadd__(self, data):
          raise TypeError("Not supported in HttpJSonResponse.")


class HttpStreamResponse(HttpResponse):
      def __init__(self, output, headers=None, status=200, content_type='application/json'):
          super(HttpStreamResponse, self).__init__(output, headers, status, content_type)

      # not supported
      def append(self, data):
          raise TypeError("Not supported in HttpStreamResponse.")

      # not supported
      def __iadd__(self, data):
          raise TypeError("Not supported in HttpStreamResponse.")


class HttpRequest(object):
    # Maximum size of memory buffer for body in bytes.
    MEMFILE_MAX = 102400

    def __init__(self, environ):
        self._environ = environ
        self.path = self._environ.get('PATH_INFO', '/')

    @cache_property
    def __body(self):
        maxread = int(self._environ.get('CONTENT_LENGTH', 0))
        stream = self._environ['wsgi.input']
        body = BytesIO() if maxread < self.MEMFILE_MAX else TemporaryFile(mode='w+b')
        while maxread > 0:
            part = stream.read(min(maxread, self.MEMFILE_MAX))
            if not part: break
            body.write(part)
            maxread -= len(part)
        self.environ['wsgi.input'] = body
        body.seek(0)
        return body

    def __to_unicode(self, data, enc='utf8'):
        if isinstance(data, unicode):
            try:
                return data.encode(enc)
            except UnicodeError, e:
                raise
        else:
            return str(data)

    @cache_property
    def __buildFormPostKeyValMap(self):
        post_data = {}
        if self.method not in ('POST','PUT'):
           return post_data

        self.__body.seek(0)
        raw_data = cgi.FieldStorage(fp=StringIO.StringIO(self.__body), environ=self._environ, keep_blank_values=True)

        data = None
        for field in raw_data:
            data = raw_data[field]
            if isinstance(data, list):
                # it's list
                post_data[field] = [fs.value for fs in data]
            elif data.filename:
                # it's file
                post_data[field] = data
            else:
                post_data[field] = data.value

        return post_data

    def is_xhr(self):
        return self._environ.get('HTTP_X_REQUESTED_WITH', '') == 'XMLHttpRequest'

    def get_method(self):
        return self._environ.get('REQUEST_METHOD', 'GET').upper()

    def get_headers(self):
        env = {}

        if self._environ['__adobopy_headers']:
           return self._environ['__adobopy_headers']

        util.as_immutable(env)

        for k, v in self._environ.items():
            if isinstance(k, unicode):
               k = k.upper().replace('-', '_')
               if k not in ('CONTENT_LENGTH', 'CONTENT_TYPE'):
                  env['HTTP_' + k] = __to_unicode(v)
               else:
                  v = __to_unicode(v)
                  env['HTTP_' + k] = v
                  env[k] = v

        self._environ['__adobopy_headers'] = env
        return env

    def get_cookies(self):
        if self._environ['__adobopy_cookies']:
           return self._environ['__adobopy_cookies']

        cookie = Cookie.SimpleCookie(self._environ.get('HTTP_COOKIE', ''))
        for k, v in cookie.values():
            cookie[k] = str(urllib.unquote(v))

        self._environ['__adobopy_cookies'] = cookie
        return cookie

    def get_post_values(self):
        return self.__buildFormPostKeyValMap()

    def get_put_values(self):
        return self.__buildFormPostKeyValMap()

    def get_get_values(self):
        if self._environ['__adobopy_get_vals']:
           return self._environ['__adobopy_get_vals']

        try:
            from urlparse import parse_qs
        except ImportError:
            from cgi import parse_qs

        get_vals = parse_qs(self._environ.get('QUERY_STRING', ''), keep_blank_values=True)
        self._environ['__adobopy_get_vals'] = get_vals
        return get_vals

    # set python style property
    method = property(get_method, None, None)
    HEADERS = property(get_headers, None, None)
    POSTS = property(get_post_values, None, None)
    PUTS = property(get_put_values, None, None)
    GETS = property(get_get_values, None, None)
    COOKIES = property(get_cookies, None, None)


def redirect(url, status_code=302):
    hdr=[('Location', url)]
    return HttpResponse(headers=hdr, status=status_code)

# DECORATORS

def GET(url, mime_type='text/html'):
    """Registers a method as capable of processing GET requests."""
    def_app = DefaultHttpRequestHandler()
    return def_app.RequestMap(url, methods=['GET'], produces=mime_type)

def POST(url, mime_type='text/html'):
    """Registers a method as capable of processing POST requests."""
    def_app = DefaultHttpRequestHandler()
    return def_app.RequestMap(url, methods=['POST'], produces=mime_type)

def PUT(url, mime_type='text/html'):
    """Registers a method as capable of processing PUT requests."""
    def_app = DefaultHttpRequestHandler()
    return def_app.RequestMap(url, methods=['PUT'], produces=mime_type)

def HEAD(url, mime_type='text/html'):
    """Registers a method as capable of processing HEAD requests."""
    def_app = DefaultHttpRequestHandler()
    return def_app.RequestMap(url, methods=['HEAD'], produces=mime_type)

def DELETE(url, mime_type='text/html'):
    """Registers a method as capable of processing DELETE requests."""
    def_app = DefaultHttpRequestHandler()
    return def_app.RequestMap(url, methods=['DELETE'], produces=mime_type)


# SERVER ADAPTERS

def run_with_wsgiref(config):
    from wsgiref.simple_server import make_server
    server = make_server(config['host'], config['port'], config['request_handler'])
    server.serve_forever()

def run_with_gevent(config):
    from gevent import pywsgi
    pywsgi.WSGIServer((config['host'], config['port']), config['request_handler']).serve_forever()
    #TODO: check spawn=None 
    
def run_with_eventlet(config):
    from eventlet import wsgi, listen
    wsgi.server(listen((config['host'], config['port']), backlog=500), config['request_handler'], max_size=8000)

def run_with_fapws3(config):
    import fapws._evwsgi as evwsgi
    from fapws import base, config

    evwsgi.start(config['host'], config['port'])
    evwsgi.set_base_module(base)
    evwsgi.wsgi_cb(('', config['request_handler']))
    evwsgi.set_debug(0)
    evwsgi.run()


WSGI_ADAPTERS = {
    'wsgiref': run_with_wsgiref,
    'gevent': run_with_gevent,
    'eventlet': run_with_eventlet,
    'fapws3': run_with_fapws3
}

def start_server(server='wsgiref', host=None, port=None, debug=False, config=None):
    if not server in WSGI_ADAPTERS:
        raise RuntimeError("Server '%s' is not a valid server. Valid servers are: " % server
              , ",".join(k for (k,v) in WSGI_ADAPTERS.items()))

    if config is None:
       config = {}

    if not host is None:
       config.update({'host':str(host)})
    else:
       config.update({'host':'localhost'})

    if not port is None:
       config.update({'port':int(port)})
    else:
       config.update({'port':8080})

    config.update({'debug':debug})

    if not 'port' in config:
       raise RuntimeError("Startup error. Server Port must be specified")

    if not 'host' in config:
       raise RuntimeError("Startup error. Host Address must be specified")

    http_handler = None

    try:
        if not 'request_handler' in config:
           http_handler = DefaultHttpRequestHandler(debug_enabled=debug)
        else:
           http_handler = config['request_handler']
           if not util.is_callable(http_handler) or not isinstance(http_handler, HttpRequestHandler):
              raise RuntimeError("Startup error. Specified request_handler is not valid adbobopy.web.HttpRequestHandler.")

        config.update({'request_handler':http_handler})

        server_adapter = WSGI_ADAPTERS[server]
        config.update({'server':server})
        
        print
        print 'Starting AdoboPy Webserver'
        print 'Using run config options:'
        for k,v in config.items():
            if 'request_handler' == k:
                v = v.__class__.__name__
            else:
                v = str(v)
                
            print '  %s = %s' % (k, v)
        print
        print 'Use Ctrl-C to quit.'
        print

        server_adapter(config)
    except KeyboardInterrupt:
        print 'Server has been shutdowned'
        
    except (Exception, SystemExit, MemoryError):
        exc_type, exc_value, exc_traceback = sys.exc_info()
        print 'Shutting down due error encountered : '
        traceback.print_exc()

