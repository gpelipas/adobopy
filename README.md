# adobopy

My Python Web Development Framework inspired by web.py and bottle.py

#####Example:
```python
#!/usr/bin/env python
# -*- coding: utf-8 -*-

from adobopy import web

web.log_method_mapping = True

@web.GET('/helloworld')
def SayHelloWorld(request, response):
    return "Hello World"

@web.GET('/wazzapp')
def Waazzzuppp(request, response):
    return "Waazzzuppp"

if __name__ == '__main__':
    web.start_server(server='gevent', debug=True)
    
```
