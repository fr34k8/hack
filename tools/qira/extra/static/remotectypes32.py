import remoteobj
import socket

if __name__ == "__main__":
  # Server
  try:
    from sys import argv
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(argv[1])
    remoteobj.Connection(sock, argv[2]).runServer(__import__('ctypes'))
  except:
    print 'The remotectypes32 process is angrily exiting.',
    raise
  exit(0)

# Client
import sys, os, subprocess, atexit
secret = os.urandom(20).encode('hex')
sockpath = '/tmp/remotectypes32.sock'+os.urandom(4).encode('hex')

sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(sockpath)
atexit.register(os.remove, sockpath)
sock.listen(1)

for path in (os.environ.get('PYTHON32'), os.path.dirname(os.path.realpath(__file__))+'/python32/Python/python'):
  if path and os.path.isfile(path):
    python32 = (path,)
    break
else:
  if sys.platform == 'darwin':
    python32 = ('/usr/bin/arch', '-i386', '/System/Library/Frameworks/Python.framework/Versions/Current/bin/python2.7')
  else:
    raise Exception('Set env variable PYTHON32 to an i386 python.')

# ida process output redirected to /dev/null
#p = subprocess.Popen(python32+(__file__, sockpath, secret), stdout=open(os.devnull,'w'))
p = subprocess.Popen(python32+(__file__, sockpath, secret))

sock, addr = sock.accept()
conn = remoteobj.Connection(sock, secret)
ctypes = conn.connectProxy()

def finishup():
  if conn: conn.disconnect()
  from time import sleep
  for i in (0.1, 0.3, 0.5):
    if p.poll() is not None: break
    sleep(i)
  else:
    p.kill()
atexit.register(finishup)

def remote_func(f):
  g = conn.deffun(f, set(f.__code__.co_names), ())
  conn._exec('for k, v in ctypes.__dict__.iteritems(): g.__globals__[k] = v', {'ctypes':ctypes, 'g':g})
  return g

__all__ = ['remote_func']

# Make `from remotectypes32 import *` work as expected
d = conn._eval("{k:v for k, v in ctypes.__dict__.iteritems() if not (k.startswith('__') and k.endswith('__'))}", {'ctypes':ctypes})
locals().update(d)
__all__.extend(d.iterkeys())

