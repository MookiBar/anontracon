#!/usr/bin/env python
from __future__ import print_function
import stem
import time
import sys
import threading
import logging
import traceback
import code
import signal
import re
import pdb
import zmq
import stat
import stem.connection as StemConnection
import os
import json
import subprocess
import Queue
import grp
from stem.control import Controller, EventType
from stem.control import Signal as StemSignal

atc_folder = '/usr/share/anontracon'
sys.path.insert(0, atc_folder)

from digraphs import digraphs

atc_agent_version = "@@VERSION@@"

#torstarter_logfilename = '/tmp/atc_tor_starter.log'

enable_debugging = True
debugging_file = '/tmp/atc_agent.debug'

def debugout(tmpstr):
  if enable_debugging:
    if debugging_file:
      with open(debugging_file,'a+') as filey:
        filey.write('%s\n' % tmpstr)
    else:
      sys.stderr.write('%s\n' % tmpstr)

############# START LOGGING CONFIG ################################
def _create_log(logfilename):
  logger = logging.getLogger('atc_agent_logger')
  #logger.setLevel(logging.DEBUG)
  logger.setLevel(logging.WARNING)
  #loggerfh = logging.FileHandler('/tmp/atc_agent.log')
  loggerfh = logging.FileHandler(logfilename)
  loggerfh.setLevel(logging.DEBUG)
  loggerch = logging.StreamHandler()
  loggerch.setLevel(logging.ERROR)
  loggerformatter = logging.Formatter('%(asctime)s: %(name)s: %(levelname)s: %(message)s')
  loggerfh.setFormatter(loggerformatter)
  loggerch.setFormatter(loggerformatter)
  logger.addHandler(loggerfh)
  logger.addHandler(loggerch)
  return logger

################ END LOGGING CONFIG ################################
#
#

myprogram = 'anontracon_agent'
#XXX my_program_dir = '/usr/share/anontracon'
#XXX my_module_dir = my_program_dir + '/modules'
#XXX if my_module_dir not in sys.path:
#XXX  sys.path.insert(0, my_module_dir)
#XXX try:
#XXX   import digraphs
#XXX except:
#XXX   raise Exception("Unable to import from anontracon")
#XXX   sys.exit()
import digraphs



  #tor_process = stem.process.launch_tor_with_config(
  #  config = {
  #    'SocksPort': str(SOCKS_PORT),
  #    'ExitNodes': '{ru}',
  #  },
  #  init_msg_handler = print_bootstrap_lines,
  #)

  # if controller.is_authenticated(): print "we're authenticated"
  # if controller.is_alive(): print "connx good"

  # if controller.is_geoip_unavailable(): print "where's geo db?"

  # my_statuses = controller.get_network_statuses()
  # for itemx in my_statuses:
  #   if blabla in itemx.fingerprint:
  ####### keys: dir_port, published, or_port, _unrecognized_lines, _archive_path, version, flags, _raw_contents, fingerprint, address, document, nickname, version_line, digest, _path

  ###(from arm) return conn.getInfo("ip-to-country/%s" % self.ipAddr, default)

  # controller.get_info('ip-to-country/%s' % exit_ip)

  # my_exit_policy = controller.get_conf('ExitPolicy') # may be a list
  ##### can this be used for hidservs?
  # my_hs_dirs = controller.get_conf('HiddenServiceDir')
  # my_hs_ports = controller.get_conf('HiddenServicePorts')

  # my_hs_dirsnports = controller.get_conf_map('HiddenServiceOptions')

     



class AsynchronousFileReader(threading.Thread):
  '''
  Helper class to implement asynchronous reading of a file
  in a separate thread. Pushes read lines on a queue to
  be consumed in another thread.
  Original code: Stefaan Lippens
  modified to take commands that auto feed from the queue.
  ''' 
  def __init__(self, fd, queue, command = None):
    try:
      assert isinstance(queue, Queue.Queue)
      assert callable(fd.readline)
      if command:
        assert callable(command)
      threading.Thread.__init__(self)
      self._fd = fd
      self._queue = queue 
      self._command = command
    except Exception, e:
      debugout('AsyncReader: INIT: FAIL!')
      debugout('%s' % repr(e) )
  def run(self):
    try:
      '''The body of the tread: read lines and put them on the queue.'''
      for line in iter(self._fd.readline, ''):
          self._queue.put(line) 
          if self._command: self._command(self._queue.get())
    except Exception, e:
      debugout('\nAsyncReader: RUN: FAIL!')
      debugout('%s' % repr(e) )

  def eof(self):
      '''Check whether there is no more content to expect.'''
      return not self.is_alive() and self._queue.empty()


#  ####events
#  import functools
#  def _got_new_stream(event):
#    print '**********************************************'
#    print '* * * * * * * * * * * * * * * * * * * * * * * '
#    print ' '
#    print type(event)
#
#  ###############

class anontraconagent():
  """Basic controller class for anontracon. TODO: finish this doc
                     __init__
  """
  atc_folder = '/usr/share/anontracon'
  atc_runfolder = '/var/run/anontracon'
  atc_lockfilepath = '/var/lock/atc'
  atc_agent_logfilename = '/tmp/atc_agent.log'
  atc_tmpfolder = '/tmp/atc'
  tor_torrc = '/etc/tor/torrc'
  tor_runfolder = '/var/run/tor'
  tor_log = '/var/log/tor/log'
  error_header = '*ERROR*:'

  def __init__(self, logger=None):
    #controller = Controller.from_port(port = 9051)
    #with Controller.from_port(port = 9051) as controller:

    #These service status codes go into the circuit dict before going to the
    #notification function. Their length is the same as normal circuit entries
    #in case the function doesn't detect them as special. Notice, the country
    #codes are numeric (00, 01, etc)...

    self.shuttingdown = False
    self.bad_connects = 0
    self._connected_to_tor = False
    self.signons = set()
    self.loglist = []

    self.logger = lambda x: debugout(repr(x))

    self.atc_hsfolder = os.path.join(self.atc_tmpfolder, 'hs')

    class fakecontroller: pass
    self.controller = fakecontroller()
    self.controller.is_authenticated = lambda: False
    self.controller.is_alive = lambda: False
    self.controller.close = lambda: True
    #because authentication may be checked before the real controller is made

    #XXX tor_starter script: our link to starting/stopping tor as root
    self.tor_starter = subprocess.Popen( \
     [ os.path.join(self.atc_folder,'tor_starter.sh') ], \
     stdin=subprocess.PIPE, \
     stderr=subprocess.STDOUT, \
     stdout=subprocess.PIPE) 
    tmpqueue = Queue.Queue()
    self.tor_starter_reader = AsynchronousFileReader( self.tor_starter.stdout, \
     tmpqueue)
    # tmpqueue, lambda x: self.broadcast_notify("tor_starter: %s" % x) )
    self.tor_starter_reader.start()
    del tmpqueue
    #self.loglist.append(torstarter_logfilename)
    #NOTE: tor_starter comes before our logger, so we have to start logging later


    #XXX make the atc folders (and change their perms later)
    for i in (self.atc_folder, self.atc_runfolder):
      if not os.path.isdir(i):
        os.makedirs(i)

    self.atc_groupid = grp.getgrnam('anontracon').gr_gid


    #XXX Parse torrc
    self.tor_controlfile = None
    self.tor_controlport = None
    if not os.path.isfile(self.tor_torrc):
      self.logger.critical("CANNOT PARSE TORRC: %s" % self.tor_torrc)
      debugout("CANNOT PARSE TORRC: %s" % self.tor_torrc)
      tmptorrc = ''
    else:
      with open(self.tor_torrc,'r') as filey:
        tmptorrc = filey.read()
    tmpresults = re.findall(r'^\w*ControlPort +([0-9]+)',tmptorrc,re.M)
    if len(tmpresults) > 0:
      try:
        self.tor_controlport = int(tmpresults[-1])
      except Exception, e:
        self.logger.exception(e)
        self.tor_controlport = None
    else:
      #XXX we can't know, so we guess....
      debugout('unable to determine control port from torrc. Aborting.')

    if stat.S_ISSOCK(os.stat(os.path.join(self.tor_runfolder,'control')).st_mode):
      self.tor_controlfile = os.path.join(self.tor_runfolder,'control')
    else:
      self.logger.critical("COULD NOT FIND CONTROL FILE IN %s" % self.tor_runfolder)
      debugout("CANNOT PARSE TORRC: %s" % self.tor_runfolder)
    if self.tor_controlfile == None and self.tor_controlport == None:
      self.logger.critical("no way to connect to TOR. Aborting...")
      sys.exit(3)

    #XXX get curr pid
    self.pid = os.getpid()


    #XXX Change uid/gid to tor's
    try: #XXX
      self.tor_uid = os.stat(self.tor_controlfile).st_uid
      self.tor_gid = os.stat(self.tor_controlfile).st_gid
    except Exception, e: #XXX
      debugout(repr(e))
      sys.exit(5)
    else: #XXX XXX XXX
      for i in (self.atc_folder, self.atc_tmpfolder, self.atc_hsfolder ):
        if not os.path.isdir( os.path.split(re.sub(r'/*$',r'',i))[0] ):
          self.logger.error(' cannot create folder %s, base directory does not exist.' % i )
        elif not os.path.isdir( i ):
          os.makedirs( i )
        try:
          os.chown(i,self.tor_uid,self.tor_gid)
        except Exception, e:
          debugout(repr(e))
      for i in ( self.atc_runfolder, ):
        try:
          os.chown(i,self.tor_uid,self.atc_groupid)
          os.chmod(i,stat.S_IRWXU | stat.S_IRWXG)
        except Exception, e:
          debugout(repr(e))
      for i in ( self.atc_agent_logfilename, ):
        try:
          if not os.path.isfile(i):
            with open( i, 'w+' ) as filey:
              filey.write('')
          os.chown(i,self.tor_uid,self.atc_groupid)
          os.chmod(i,stat.S_IRWXU | stat.S_IRWXG)
        except Exception, e:
          debugout(repr(e))


      #for i in ( os.path.join(self.atc_runfolder, 'ATCBROADCAST'),
      # os.path.join(self.atc_runfolder, 'ATCCONTROL') ):
      #  try:
      #    os.chmod( i, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
      #  except Exception, e:
      #    debugout(repr(e))
      #    debugout("WTFKSDJFLJSDFLJ")

      os.setgid(self.tor_gid)
      os.setuid(self.tor_uid)

    ##XXX XXX XXX
    ## Uncomment the next line to do lockfile checking within this script.
    ## Otherwise, you can check the lockfile for running instances of this 
    ## program and kill them from other scripts or wrapper scripts (which is
    ## recommended).
    #self.checklockfile()

    self.loglist = []
    if type(logger) == logging.Logger:
      self.logger = logger
    else:
      self.logger = _create_log(self.atc_agent_logfilename)
    self.logger.warning('start\n\n'+'*'*30+'\n'+'*'*30+'\n'+ 'starting log...')
    sys.excepthook = self.exceptyclosure()
    for j in self.logger.handlers:
      if type(j) == logging.FileHandler:
        try:
          tmpfilename = str(j.stream.name)
        except Exception, e:
          self.logger.exception(e)
        else:
          self.loglist.append(tmpfilename)
    del tmpfilename

    #now let's start logging tor_starter's output
    #TODO: is there ANY way to not do this in one more thread?

    self.tor_starter_monitor = threading.Thread( \
     target=self.monitor_async_reader, args=[ self.tor_starter_reader, \
     lambda x: self.logger.warning("tor_starter: %s" % x ) ] )
    self.tor_starter_monitor.start()
    #XXX XXX XXX asdfasdfasdf

    self.last_notification = []


    #NOTE: not using "with/as" notation is dangerous. we may spawn
    # a bunch of zombie control sockets. However, using with/as notation
    # is impossible here as the connection must persist throughout...

    #startup = building circ_dict for the first time.  subsequent changes
    # will be made by event listeners
    #circ_dict will hold all circuit ids as keys and fingerprint/nick as values
    # then we add ip, country digraph and bandwidth (if annotated
    # **not yet implemented**)

    self.curr_ip = 0
    self.curr_country = ''
    self.curr_available = []

    self.re_error_header = re.compile( re.escape(self.error_header) )
    self.re_bridgeline_all = re.compile(r'^ *(bridge +)?(obfs[1-9] +)?([0-9]{1,3}\.){3}[0-9]{1,3}:[1-9][0-9]* *( +([0-9A-Z]{4} ?){10})? *$')
    self.re_validip = re.compile(r'^([0-9]+\.){3}[0-9]+$')
    self.re_validiprange = re.compile(r'^(([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})\.){3}([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})/(4|8|12)$')
    self.re_fingerprint = re.compile(r'^\s*([A-Z0-9]{4} ?){10}\s*$')
    self.re_onionaddr = re.compile(r'^[a-z0-9]{16}\.onion$')
    self.re_validrsakey = re.compile(r'-----BEGIN RSA PRIVATE KEY-----\n([a-zA-Z0-9+/]{64}\n){12,20}[a-zA-Z0-9+/]{,64}={,4}\n-----END RSA PRIVATE KEY-----')
    #NOTE: ^^ this only works for tor's rsa keys. i.e.  with no email nor other
    #          identifying info and no password set...
    
    signal.signal(signal.SIGTERM, self._signalyhandler)
    signal.signal(signal.SIGINT, self._signalyhandler)
    signal.signal(signal.SIGUSR1, self._signalyhandler)
    signal.signal(signal.SIGUSR2, self._signalyhandler)

    self.torlog_thread = None
    self.bcast_torlog = False

    #XXX START ZMQ messaging sockets!
    #XXX these locks should be obsolete now...
    self.zmq_lock_bcast = threading.Lock()
    self.zmq_lock_cnc = threading.Lock()

    self.lock_bad_connects = threading.Lock()
    self.lock_circ_dict = threading.Lock()
    ### XXX should we make a lock for all such confs???

    debugout('xxx 1') #XXX DELME

    #XXX C&C (recv)
    self.zmq_context = zmq.Context()
    self.zmq_control_socket = self.zmq_context.socket(zmq.ROUTER)
    #TODO: allow more than one connection? (esp. since there may be
    #       more than one user...)
    #self.zmq_socket_filename = os.path.join(self.atc_run_folder, str(self.pid))
    self.zmq_control_socket_url = "ipc://" + os.path.join(self.atc_runfolder, 'ATCCONTROL')
    debugout(self.zmq_control_socket_url)
    self.zmq_control_socket.bind( self.zmq_control_socket_url)
    #TODO: RESTRICT ACCESS TO THAT SOCKET!
    self.zmq_control_socket.poll(1) #TODO: WHAT WAS THE POLLING BUG?!?!?!


    debugout('xxx 2') #XXX DELME

    #XXX BROADCAST
    self.zmq_bcast_socket = self.zmq_context.socket(zmq.PUB)
    self.zmq_bcast_socket_url = "ipc://" + os.path.join(self.atc_runfolder, 'ATCBROADCAST')
    self.zmq_bcast_socket.bind(self.zmq_bcast_socket_url)

    debugout('xxx 2 and a quarter...')

    for i in ( os.path.join(self.atc_runfolder, 'ATCBROADCAST'),
     os.path.join(self.atc_runfolder, 'ATCCONTROL') ):
      try:
        os.chmod( i, stat.S_IRWXU | stat.S_IRWXG | stat.S_IRWXO)
      except Exception, e:
        self.logger.exception(e)
        self.logger.error("could not change perms on sockets")

    debugout('xxx 2 and a half...')

    self.zmq_event_sockets = {"init":None,"cnc":None,"torlog":None,"any":None,"stream":None,"circ":None,"conf":None,"status":None,}
    for i in self.zmq_event_sockets.keys():
      #"init" only used during the init process (which uses its own thread)...
      #"bcast" only used when no other specified, requires lock...
      #most of the others are passed to stem's event listeners
      self.zmq_event_sockets[i] = self.zmq_context.socket(zmq.REQ)
      self.zmq_event_sockets[i].setsockopt(zmq.IDENTITY,i)

    self.zmq_event_socket = self.zmq_context.socket(zmq.ROUTER)
    self.zmq_event_socket.bind("inproc://atc_events")
    #self.zmq_event_socket_poller = zmq.Poller()
    #self.zmq_event_socket_poller.register(self.zmq_event_socket)
    #self.zmq_event_socket_poller.poll(1)
    self.zmq_thread_bcast = threading.Thread()
    self.zmq_thread_bcast.run = self.zmq_bcast_func
    self.zmq_thread_bcast.start()

    for i in self.zmq_event_sockets.keys():
      self.zmq_event_sockets[i].connect("inproc://atc_events")
      self.zmq_event_sockets[i].send_multipart(['XXX','XXX'])
      tmpreply = self.zmq_event_sockets[i].recv_multipart()
      if tmpreply[0] != 'XXX':
        self.logger.error('failed to finish socket initialization: expected keepalive response, got %s' % repr(tmpreply))

    debugout('xxx 3') #XXX DELME

    #XXX C&C thread
    self.zmq_thread_cnc = threading.Thread()
    self.zmq_thread_cnc.run = self.zmq_cnc_func
    self.zmq_thread_cnc.start()


    debugout('xxx 4') #XXX DELME
 
    #self.last_circ = ''
    self.curr_streams = []
    self.digraphs = digraphs.digraphs

    with self.lock_circ_dict:
      self.circ_dict = {}
    #self.circ_failed = False
    #self.stream_failed = 0
    self.all_event_listeners = []
    self.all_status_listeners = []
    #self.init_thread = threading.Thread()
    #self.init_thread.run = self.init_thread_func
    #self.init_thread.start()
    socket = self.zmq_event_sockets['init']
    #"connect_to_tor" now handles (re-)creation of listeners...
    while not self.shuttingdown:
      if not self._connect_to_tor():
        self.bcast_notify(socket,'agent.error','failed to connect to tor')
      else:
        self._connected_to_tor = True
        break 
    for i in [ \
     self.new_stream_event, 
     self.new_circ_event, 
     self.new_conf_event, 
     ]:
      self.all_event_listeners.append(i)
    for i in [ \
     self.new_status_change,
     ]:
      self.all_status_listeners.append(i)
    self.get_all_confs(socket)


    debugout('xxx 5') #XXX DELME

  ### XXX end init XXX
  ############################################################


  def init_thread_func(self):
    socket = self.zmq_event_sockets['init']
    #"connect_to_tor" now handles (re-)creation of listeners...
    while not self.shuttingdown:
      if not self._connect_to_tor():
        self.bcast_notify(socket,'agent.error','failed to connect to tor')
      else:
        self._connected_to_tor = True
        break 
    for i in [ \
     self.new_stream_event, 
     self.new_circ_event, 
     self.new_conf_event, 
     ]:
      self.all_event_listeners.append(i)
    for i in [ \
     self.new_status_change,
     ]:
      self.all_status_listeners.append(i)
    self.get_all_confs(socket)
    return True

  ########################################################

  def exceptyclosure(self):
    def exceptyhandler(ztype, zvalue, ztb):
      try:
        self.logger.critical("uncaught exception: line {0}:{1}:{2}".format(ztb.tb_lineno,str(ztype),str(zvalue)))
      except Exception:
        pass
      debugout('uncaught exception: line',str(ztb.tb_lineno),str(ztype),str(zvalue))
      #sys.stderr.flush()
      #pdb.pm()
    return exceptyhandler

  #########################################################

  def _signalyhandler(self, zsignal, zframe):
    if zsignal == 1 :
      self.logger.info('SIGHUP received')
    elif zsignal == 2 :
      self.logger.info('SIGINT received')
      self._shuterdown(zsignal)
    elif zsignal == 3 :
      self.logger.info('SIGQUIT received')
      self._shuterdown(zsignal)
    elif zsignal == 15 :
      self.logger.info('SIGTERM received')
      self._shuterdown(zsignal)
    elif zsignal == 11 :
      self.logger.info('SIGSEGV received')
      self.logger.info( '-'*30 + '\n %s \n' % ( dir(zframe) ) )
    elif zsignal == 10 :
      self.logger.info('SIGUSR1 received')
      self.logger.critical('user interrupt received. Exit info:\n %s \n ' %  \
       ( self.circ_dict[self.circ_dict['last_circ']] ) + '.'*30 )
    elif zsignal == 11 :
      self.logger.info('SIGUSR2 received')
      for i in [ 'last_circ', 'curr_streams' ]:
        self.logger.critical( '%s: %s \n' % ( i, getattr(self, i) ) \
         + '-'*30 )
      for i in circ_dict.keys():
        self.logger.critical('circ_dict: \n %s: %s' % ( i, circ_dict[i] ) )

  ###########################################################

  def _connect_to_tor(self):
    tmpreturn = False
    havecontroller = False
    bsocket = None
    try:
      if self.controller:
        try:
          if self.controller.is_authenticated():
            return True
        except Exception:
          pass
    except NameError:
      pass
    except AttributeError:
      pass
    except Exception, e:
      self.logger.exception(e)
    tmpcount = 0
    while not self.shuttingdown and not havecontroller:
      #if tor is not running (or service shut down) this will continue to fail
      if self.tor_controlfile:
        try:
          tmpcontroller = Controller.from_socket_file(path=self.tor_controlfile)
          #because something may hit our (fake?) controller before this works
          #TODO: make sure this process doesn't spawn redundant persistant
          #      control port sockets...
        except stem.SocketError, e:
          if self.tor_controlport:
            try:
              tmpcontroller = Controller.from_port(port = self.tor_controlport)
            except stem.SocketError, f:
              tmpcount += 1
              if ( tmpcount + 19 ) % 20 == 0:
                self.logger.error('failed to connect to TOR service after %s attempts using file: %s and port %s \n' % \
                 ( tmpcount, self.tor_controlfile, self.tor_controlport) )
              time.sleep(3)
            except Exception, h:
              self.logger.exception(h)
            else:
              self.controller = tmpcontroller
              havecontroller = True
        except Exception, g:
          self.logger.exception(g)
        else:
          self.controller = tmpcontroller
          havecontroller = True 
      else:
        try:
          tmpcontroller = Controller.from_port(port = self.tor_controlport)
        except stem.SocketError, f:
          tmpcount += 1
          if ( tmpcount + 19 ) % 20 == 0:
            self.logger.error('failed to connect to TOR service after %s attempts using file: %s and port %s' % \
             ( tmpcount, self.tor_controlfile, self.tor_controlport) )
          time.sleep(3)
        except Exception, h:
          self.logger.exception(h)
        else:
          self.controller = tmpcontroller
          havecontroller = True

    if havecontroller:
      tmpcount = 0
      while tmpcount < 60:
        try:
          if self.controller.is_authenticated():
            tmpreturn = True
            break
        except Exception, e:
          self.logger.exception(e)
        time.sleep(1)
        try:
          self.controller.authenticate()
        except Exception, e:
          self.logger.exception(e)
        time.sleep(2)
        tmpcount += 1
      if self.controller.is_authenticated():
        tmpreturn = True
      else:
        self.logger.critical('able to connect to TOR but unable to authenticate')
        tmpreturn = False
    else:
      tmpreturn = False

    if tmpreturn:
      self.controller.add_event_listener(self.new_stream_event, EventType.STREAM)
      self.controller.add_event_listener(self.new_circ_event, EventType.CIRC)
      self.controller.add_event_listener(self.new_conf_event, EventType.CONF_CHANGED)
      self.controller.add_status_listener(self.new_status_change)
      self.build_new_circ_dict()
      for i in self.circ_dict.keys():
        if re.match(r'^[0-9]{1,}$',i):
          #have valid circs, send it
          self.bcast_notify(bsocket,'torcirc.exit',self.circ_dict)
          break

      try:
        if self.controller.is_authenticated():
          if self.controller.get_conf('__ReloadTorrcOnSIGHUP') == '1':
            self.controller.set_conf('__ReloadTorrcOnSIGHUP','0')
      except Exception, e:
        self.logger.exception(e)
    return tmpreturn 

  ###########################################################

  def _shuterdown(self, zsignal=0):
    self.bcast_notify(None,'atc.shutdown',True)

    self.shuttingdown = True
    self.logger.warning('shutting down (signal: %s )\n\n' % str(zsignal))

    self.tor_starter.stdin.write('X')
    time.sleep(1)

    debugout('xyz1')

    for i in (self.new_stream_event,self.new_conf_event,self.new_circ_event):
      try:
        self.controller.remove_event_listener(i)
      except Exception as e:
        self.logger.exception(e)

    debugout('xyz2')

    for i in (self.new_status_change,):
      try:
        self.controller.remove_status_listener(i)
      except Exception as e:
        self.logger.exception(e)

    debugout('xyz3')

    #XXX XXX XXX TODO:  shutdown currently stops right here when a zmq assertion
    #                   fails for the first of these sockets. How to fix...?
    for socky in [ self.zmq_control_socket, self.zmq_event_socket, self.zmq_bcast_socket, ] + self.zmq_event_sockets.values():
      try:
        if socky.poll(1):
          socky.recv_multipart()
      except Exception:
        pass
      socky.close()

    debugout('xyz4')

    try:
      self.zmq_context.term()
    except Exception, e:
      self.logger.exception(e)

    debugout('xyz5')

    self.controller.close()
    sys.exit(zsignal)

  ###########################################################

  def bcast_notify(self,bsocket,intype,indata):
    """Takes three arguments:
      - a 0mq REQ socket (to route to the broadcast socket)
      - a broadcast identifier
      - broadcast data (a json-compatible python object)
    Sends a multipart broadcast (with identifier and json-ified
    data) over 0mq broadcast socket.

    Valid identifiers: 'atc.error','atc.shutdown',
                       'torcirc.exit','torcirc.entry',
                       'torconf.hs','torconf.bridges','torconf.goodexits',
                       'torconf.badexits','torconf.other',
                       'tor.log','torstatus'
    (any other info is only by individual request via the 
    command-n-control socket)
    """
    #NOTE: everything has to be STRICTLY ASCII over the wire...
    #       Json SHOULD take care of that...
    #     The socket argument is because this will be called from
    #      different threads that would/should use different 0mq-
    #      sockets...
    intype = str(intype)
    if intype == 'atc.error':
      jindata = self.errify(indata)
    else:
      jindata = self.zmqify(indata)


    if bsocket == None:
      with self.zmq_lock_bcast:
        try:
          #self.zmq_bcast_socket.send_multipart([jintype,jindata])
          self.zmq_event_sockets['any'].send_multipart([intype,jindata])
        except Exception, e:
          self.logger.exception(e)
          self.logger.error("could not broadcast data: \n %s\n %s\n" % \
           (intype,indata))
        else:
          tmpreply = self.zmq_event_sockets['any'].recv_multipart()
          if tmpreply == [ intype, self.zmqify(True) ]:
            return True
          else:
            return False
    else:
      try:
        intype = str(intype)
        jindata = self.zmqify(indata)
      except Exception, e:
        self.logger.exception(e)
        return False
      try:
        #self.zmq_bcast_socket.send_multipart([jintype,jindata])
        bsocket.send_multipart([intype,jindata])
      except Exception, e:
        self.logger.exception(e)
        self.logger.error("could not broadcast data: \n %s\n %s\n" % \
         (intype,indata))
      else:
        tmpreply = bsocket.recv_multipart()
        if tmpreply == [ intype, self.zmqify(True) ]:
          return True
        else:
          return False

  ###########################################################

  def cnc_send(self,sender,intype,indata=None):
    #NOTE: everything has to be STRICTLY ASCII

    debugout("cnc_send start") #XXX DEBUGGING
    debugout("cnc_send args: %s %s %s" % \
     ( repr(sender), repr(intype), repr(indata)  ) ) #XXX DEBUGGING

    csocket = self.zmq_control_socket
    bsocket = self.zmq_event_sockets['cnc']

    if intype == 'XXX':
      try:
        csocket.send_multipart([sender,'','XXX'])
      except Exception, e:
        self.logger.exception(e)
        self.bcast_notify( bsocket, 'atc.error', e )
        return False
      else:
        return True

    elif not type(intype) == str:
      self.logger.error('cnc_send: first argument must be string, not %s' % \
       repr(type(intype)) )
      self.cnc_send_error( sender, intype, \
       TypeError('type identifier must be a string') )
      return False

    else:
      # (almost) everything should be done here...
      if isinstance(indata, Exception):
        self.cnc_send_error( sender, intype, indata )
        return True
      else:
        jindata = self.zmqify(indata)
      with self.zmq_lock_cnc:
        try:
          csocket.send_multipart([sender,'',intype,jindata])
          ## ^^^ the MOST important cnc delivery
        except Exception, e:
          self.logger.exception(e)
          try:
            csocket.send_multipart([sender,'','agent.error',self.errify(e)])
          except Exception, f:
            self.logger.exception(f)
            self.bcast_notify( bsocket, 'agent.error', self.errify(e) )
            self.bcast_notify( bsocket, 'agent.error', self.errify(f) )
          return False
        else:
          return True
      

  ###########################################################

  def cnc_send_error(self, sender, intype, exceptiony):
    """ send reply to a sender using same input type. last argument 
    may be an exception or a string """

    debugout("CNC SEND ERROR START \n") #XXX DEBUGGING

    csocket = self.zmq_control_socket
    bsocket = self.zmq_event_sockets['cnc']

    if isinstance(exceptiony, Exception):
      tmpstr = "%s %s" % ( self.error_header, repr(exceptiony)  )
    elif type(exceptiony) == str or type(exceptiony) == unicode:
      tmpstr = "%s %s" % ( self.error_header, exceptiony )
    else:
      debugout( "WTF BAD EXCEPTION WRITING \n") #XXX DEBUGGING
      self.logger.error("bad cnc exception: %s" % repr(exceptiony))
      tmpstr = "%s see agent logs" % self.error_header
    try:
      csocket.send_multipart([sender,'',intype,tmpstr])
    except Exception, e:
      self.logger.exception(e)
      debugout("SUPER EXCEPTION FAIL \n") #XXX DEBUGGING
      self.bcast_notify( bsocket, intype, e )
      

  ##########################################################

  def errify(self,exceptiony):
    """ take a string or exception and return a string in the proper format
    for sending over zmq """

    if isinstance(exceptiony, Exception):
      tmpstr = "%s %s" % ( self.error_header, repr(exceptiony)  )
    elif type(exceptiony) == str or type(exceptiony) == unicode:
      tmpstr = "%s %s" % ( self.error_header, exceptiony )
    else:
      debugout( "WTF BAD ERRIFY INPUT \n") #XXX DEBUGGING
      self.logger.error("bad input for errify: %s" % repr(exceptiony))
      tmpstr = "%s see agent logs" % self.error_header
    return tmpstr

  ##########################################################

  def zmqify(self,pyobject):
    """ take a python object and return a string in the proper format
    for sending over zmq """

    if isinstance( pyobject, Exception):
      tmpstr = "%s %s" % ( self.error_header, repr(exceptiony)  )
    else:
      try:
        tmpstr = json.dumps( pyobject , ensure_ascii=True)
      except Exception, e:
        tmpstr = "%s %s" % ( self.error_header, repr(e) )
    return tmpstr


  ###########################################################

  def unzmqify(self,jsonobject):
    """ take a json string and return a python object"""

    try:
      tmpobj = json.loads(jsonobject,ensure_ascii=True)
      tmpobj = self.stringify(tmpobj)
      ##NOTE: ^^ ensure it's a string because stem freaks out with unicode (it
      ##         starts seeing a byte-array instead of a string)
    except ValueError:
      tmpobj = jsonobject
    except Exception, e:
      self.logger.exception(e)
      return e

    return tmpobj


  ###########################################################

  def stringify(self,unicodeobject):
    """Take a Python object that was converted from JSON and turn it (if
    it's unicode) or any unicode objects within it into string objects. 
    This is necessary to make the object compatible with STEM."""
    ## yep, a function that's MEANT to recursively call itself...
    ##  .... because I'm crrrraaAAAAaaaaazzzy....
    def _recursive_checkifier(zz):
      if type(zz) == str:
        return zz
      elif type(zz) == unicode:
        return str(zz)
      elif type(zz) == list:
        return [ _recursive_checkifier(x) for x in zz ]
      elif type(zz) == dict:
        tmpdict = {}
        for i in zz.keys():
          tmpdict[_recursive_checkifier(i)] = _recursive_checkifier(zz[i])
        return tmpdict
      else:
        return zz
    return _recursive_checkifier(unicodeobject)

  #######################################################

  def zmq_bcast_func(self):
    bsocket = self.zmq_bcast_socket
    esocket = self.zmq_event_socket
    ## ^^^ get stuff from the event socket and broadcast it


    while not self.shuttingdown:
      if esocket.poll(100):
        try:
          #NOTE: should be receiving an iterable of length 4, of which the
          #      last two is the important stuff: a string for the type
          #      of request and a json object with any relevant data (or 
          #      an empty string if not applicable)
          #        e.g. [ sender,'','is_authenticated','true' ]
          tmpincoming = esocket.recv_multipart()
        except Exception, e:
          self.logger.exception(e)
          tmpexception = self.errify(e)
          bsocket.send_multipart( [ 'atc.error', tmpexception ] )
        else:
          if len(tmpincoming) > 2 and tmpincoming[1] == '' and tmpincoming[2]:
            ## ^ looks like normal routed traffic: has four parts, a sender, 
            ##    a nullstring delimiter, a topic and data of any/null type
            sender = tmpincoming[0]
            intype = tmpincoming[2]

            if intype == 'XXX':
              #self.cnc_send(sender,'XXX','XXX')
              esocket.send_multipart([sender,'','XXX','XXX']) #XXX
              bsocket.send_multipart(['XXX','XXX']) #XXX
              ### ^^ for debugging purps.
            #elif intype == 'is_authenticated':
            #  self.cnc_send(sender,intype,self.cnc_is_authenticated())
            #  else:
            #    self.logger.error('received unknown command type: %s' % intype) 
            #    self.cnc_send(sender,intype, ValueError('not a valid command'))
            else:
              if len(tmpincoming) > 3:
                indata = tmpincoming[3]
              else:
                indata = ''
              #  indata = self.zmqify(tmpincoming[3])
              #else:
              #  indata = self.zmqify('')
              ## ^^^ no. trust the events to give you good json
              #with open('/tmp/bcastoutz','a+') as filey: #XXX DEBUGGING
              #  filey.write(repr(tmpincoming) + '\n\n') #XXX XXX XXX DEBUGGING!
              
              try:
                bsocket.send_multipart([ intype, indata ])
              except Exception, e:
                tmpexcystring = self.errify(e)
                try:
                  esocket.send_multipart( [sender,'',intype, tmpexcystring ] )
                except Exception, f:
                  debugout("COMPLETE BCAST FAIL x1 \n") #XXX DEBUGGING
                  bsocket.send_multipart(['atc.error',tmpexcystring])
                  bsocket.send_multipart(['atc.error',self.errify(f)])
              else:
                esocket.send_multipart([sender,'',intype,json.dumps(True)])

          else:
            self.logger.error("sender with no data or no data-delimiter: %s" % \
             repr(tmpincoming))
            bsocket.send_multipart(['atc.error', errify( AttributeError( \
             "malformed data stream or missing data for input")) ])
    bsocket.close()
    esocket.close()
 


  ###########################################################

  def zmq_cnc_func(self):
    """Continuously polls the command-n-control socket for requests.
    This function should only be run by the cnc thread!
    Requests sent over the socket should be mulipart (2 elements): a
    string identifier and a json object (or null string if not applicable).

    Accepted identifiers and the json object that's expected:
      'is_authenticated':'' (nullstring = <ignored>)
      'add_goodexits':list  (['1.2.3.4','us'])
      'set_goodexits':list  (['1.2.3.4','us'])
      'get_goodexits':''
      'add_badexits':list  (['1.2.3.4','us'])
      'set_badexits':list  (['1.2.3.4','us'])
      'get_badexits':''
      'add_badnodes':list  (['1.2.3.4','us'])
      'set_badnodes':list  (['1.2.3.4','us'])
      'get_badnodes':''
      'get_entrynodes':''
      'add_hs':list   ([ ['/my/dir','99 127.0.0.1:99'], ])
      'set_hs':list   ([ ['/my/dir','99 127.0.0.1:99'], ])
      'get_hs':''
      'get_hsinfo':list   (['/my/dir','99 127.0.0.1:99'])
      'add_bridges':list  (['1.2.3.4','4.3.2.1',])
      'set_bridges':list  (['1.2.3.4','4.3.2.1',])
      'get_bridges':''
      'set_signal':str    ('NEWNYM')
      'get_iplocation':str ('1.2.3.4')
      'get_supportedobfs':''
      'get_agentlogfiles':''
      'set_bcasttorlog':bool  (True)
      'get_allconfs':''
    (Note: Sorry. This is what it looks like converted to python. I will
     show the actual json later...)
       """
    bsocket = self.zmq_event_sockets['cnc']
    ## ^^^ in case we need to turn a cnc request into a broadcast
    csocket = self.zmq_control_socket
    ## ^^^ receive/reply to requests
    assert hasattr(bsocket, 'recv')
    assert hasattr(csocket, 'recv')
    while not self.shuttingdown:
      if csocket.poll(100):
        try:
          debugout("CNC POLLED!")
          #NOTE: should be receiving an iterable with just two parts: a string
          #      of the type of request and a dict with any relevant data (or 
          #      None type if empty or not applicable)
          #        e.g. ('is_authenticated',None)
          #             ('set_conf',('ExitNodes','12.34.56.78,de,us'))
          #             ('set_options',(('HiddenServiceDir','/my/hidden/service'),('HiddenServicePort','1234')))
          #             ('reset_conf','HiddenServiceOptions')
          tmpincoming = csocket.recv_multipart()
          debugout("RECEIVED") #XXX DEBUGGING
          incoming = tmpincoming
          self.logger.debug("received incoming: %s" % repr(incoming))
        except Exception, e:
          debugout("BAD POLLY") #XXX DEBUGGING
          self.logger.exception(e)
          self.bcast_notify(bsocket,'atc.error',e)
        else:
          debugout("GOOD POLLY") #XXX DEBUGGING
          debugout(repr(incoming))
          if len(incoming) > 2 and incoming[1] == '':
  #XXX XXX
            debugout("xa1") #XXX DEBUGGING
            sender = incoming[0]
            intype = incoming[2]
            debugout("intype: %s" % repr(intype) ) #XXX DEBUGGING
            if len(incoming) > 2 and type(intype) == str:
              if intype == 'XXX':
                self.cnc_send(sender,'XXX','XXX')
                debugout("xxx") #XXX DEBUGGING
                continue
              elif len(incoming) > 3:
                if incoming[3] == '':
                  indata = None
                else:
                  try:
                    indata = json.loads(incoming[3])
                    indata = self.stringify(indata)
                    ##NOTE: ^^ ensure ascii because stem freaks out 
                    ##         with unicode (it starts seeing a byte-array 
                    ##         instead of a string)

                  except Exception, e:
                    self.logger.exception(e)
                    self.cnc_send(sender,intype,e)
                    continue
              else:
                indata = None

              debugout("indata: %s" % repr(indata) ) #XXX DEBUGGING
    
              if intype == 'is_authenticated':
                self.cnc_send(sender,intype,self.cnc_is_authenticated())
    
              elif intype == 'add_goodexits':
                self.cnc_send(sender,intype, \
                 self.cnc_add_goodexits( indata ) )
              elif intype == 'set_goodexits':
                self.cnc_send(sender,intype, \
                 self.cnc_set_goodexits( indata ) )
    
              elif intype == 'get_goodexits':
                self.cnc_send(sender,intype, \
                 self.cnc_get_goodexits() )
    
              elif intype == 'add_badexits':
                self.cnc_send(sender,intype, \
                 self.cnc_add_badexits( indata ) )
              elif intype == 'set_badexits':
                self.cnc_send(sender,intype, \
                 self.cnc_set_badexits( indata ) )
              elif intype == 'get_badexits':
                self.cnc_send(sender,intype, \
                 self.cnc_get_badexits() )
    
              elif intype == 'add_badnodes':
                self.cnc_send(sender,intype, \
                 self.cnc_add_badnodes( indata ) )
              elif intype == 'set_badnodes':
                self.cnc_send(sender,intype, \
                 self.cnc_set_badnodes( indata ) )
              elif intype == 'get_badnodes':
                self.cnc_send(sender,intype, \
                 self.cnc_get_badnodes() )
    
              elif intype == 'get_entrynodes':
                self.cnc_send(sender,intype,
                 self.cnc_get_entrynodes() )
    
              elif intype == 'add_hs':
                self.cnc_send(sender,intype, \
                 self.cnc_add_hs(indata) )
              elif intype == 'set_hs':
                self.cnc_send( sender,intype, \
                 self.cnc_set_hs(indata) )
              elif intype == 'get_hs':
                self.cnc_send( sender,intype, self.cnc_get_hs() )
              elif intype == 'get_hsinfo':
                self.cnc_send( sender,intype, self.cnc_get_hsinfo(indata) )
              
   
              elif intype == 'add_bridges':
                self.cnc_send( sender,intype, \
                 self.cnc_add_bridges( indata ) )
              elif intype == 'set_bridges':
                self.cnc_send( sender,intype,
                 self.cnc_set_bridges( indata ) )
              elif intype == 'get_bridges':
                self.cnc_send(sender,intype, \
                 self.cnc_get_bridges() )
    
              elif intype == 'set_signal':
                self.cnc_send(sender,intype, \
                 self.cnc_set_signal( indata ) )
    
              elif intype == 'get_iplocation':
                self.cnc_send(sender,intype,
                 self.cnc_get_iplocation( indata ))
    
              elif intype == 'get_supportedobfs':
                self.cnc_send(sender,intype,
                 self.cnc_get_supportedobfs() )
    
              elif intype == 'get_agentlogfiles':
                self.cnc_send(sender,intype,
                 self.cnc_get_agentlogfiles() )
  
              elif intype == 'set_bcasttorlog':
                if indata == True:
                  self.bcast_torlog = True
                  if not self.torlog_thread:
                    self.torlog_thread = threading.Thread()
                    self.torlog_thread.run = lambda: self.LogFollow(self.tor_log, \
                     self.zmq_event_sockets['torlog'], "tor.log",allofit = True)
                    self.torlog_thread.start()
                    self.cnc_send(sender,intype,True)
                  else:
                    self.cnc_send(sender,intype,True)
                elif indata == False:
                  self.bcast_torlog = False
                  if self.torlog_thread:
                    try:
                      self.torlog_thread.join()
                    except Exception, e:
                      self.logger.exception(e)
                  del self.torlog_thread
                  self.torlog_thread = None
                  self.cnc_send(sender,intype,True)
                
    
              elif intype == 'set_broadcastresponses':
                #XXX this is not to be used yet
                self.cnc_send( sender,intype, \
                 AttributeError('not yet supported'))

              elif intype == 'get_allconfs':
                self.cnc_send( sender,intype, \
                 self.cnc_getallconfs(bsocket))
              else:
                debugout("badx2") #XXX DEBUGGING
                self.logger.error('received unknown command type: %s' % intype) 
                self.cnc_send(sender,intype, ValueError('not a valid command'))
            else:
              debugout("badx1 \n") #XXX DEBUGGING
              self.logger.error("bad format for input: %s" % repr(incoming))
              self.bcast_notify(bsocket,'atc.error',
               ValueError('malformed data or missing arguments for input stream') )
          else:
            debugout("badx0 \n") #XXX DEBUGGING
            self.logger.error("sender with no data or no data-delimiter: %s" % \
             repr(tmpincoming))
            self.bcast_notify( bsocket, 'atc.error', AttributeError("malformed data stream or missing data for input"))
    bsocket.close()
    #asdfasdfasdf XXX

  #---------------------------------------------
  def cnc_is_authenticated(self):
    try:
      response = self.controller.is_authenticated()
    except Exception, e:
      self.logger.exception(e)
      response = e
    return response
  #---------------------------------------------
  def cnc_add_goodexits(self,tmplist):
    try:
      tmpexits = self.controller.get_conf('ExitNodes')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if len(tmpexits) > 0:
        tmpcurrexits =  tmpexits.split(',')
      else:
        tmpcurrexits = []

    if type(tmplist) == None:
      outdata = None
    elif type(tmplist) == list:
      if len(tmplist) == 0 or ( len(tmplist) == 1 and tmplist[0] == '' ):
        outdata = None
      else:
        tmpgoodentries = []
        for i in tmplist:
          if re.match(r'\{..\}$',i) and \
           not i.strip('{}') in self.digraphs.keys():
            tmpgoodentries.append(i)
            debugout("\n\nERROR DIGRAPHY1\n\n") #XXX DEBUGGING
          elif not re.match(self.re_fingerprint, i) and \
           not re.match(self.re_validip, i) and \
           not re.match(r'\{..\}$',i) and \
           not re.match(self.re_validiprange, i):
            tmpgoodentries.append(i)
        if len(tmpgoodentries) > 0:
          self.logger.error( 'invalid command entries received: %s (should be fingerprint, ip or digraph)' % \
           ( ','.join(tmpgoodentries) ) )
          return ValueError("invalid entries: %s" % ",".join(tmpgoodentries))
        else:
          outdata = ','.join(tmplist + tmpcurrexits)
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    debugout("\n\nOUTDATA: %s: %s\n\n" % \
     ( type(outdata), outdata) ) #XXX DEBUGGING
    try:
      self.controller.set_conf('ExitNodes',outdata)
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      return True

  #---------------------------------------------
  def cnc_set_goodexits(self,tmplist):
    if type(tmplist) == None:
      outdata = None
    elif type(tmplist) == list:
      if len(tmplist) == 0 or ( len(tmplist) == 1 and tmplist[0] == '' ):
        outdata = None
      else:
        tmpgoodentries = []
        for i in tmplist:
          if re.match(r'\{..\}$',i) and \
           not i.strip('{}') in self.digraphs.keys():
            tmpgoodentries.append(i)
            debugout("\n\nERROR DIGRAPHY1\n\n") #XXX DEBUGGING
          elif not re.match(self.re_fingerprint, i) and \
           not re.match(self.re_validip, i) and \
           not re.match(r'\{..\}$',i) and \
           not re.match(self.re_validiprange, i):
            tmpgoodentries.append(i)
        if len(tmpgoodentries) > 0:
          self.logger.error( 'invalid command entries received: %s (should be fingerprint, ip or digraph)' % \
           ( ','.join(tmpgoodentries) ) )
          return ValueError("invalid entries: %s" % ",".join(tmpgoodentries))
        else:
          outdata = ','.join(tmplist)
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    debugout("\n\nOUTDATA: %s: %s\n\n" % \
     ( type(outdata), outdata) ) #XXX DEBUGGING
    try:
      self.controller.set_conf('ExitNodes',outdata)
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      return True

  #---------------------------------------------
  def cnc_get_goodexits(self):
    try:
      tmpexits = self.controller.get_conf('ExitNodes')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if len(tmpexits) > 0:
        return tmpexits.split(',')
      else:
        return []
  #---------------------------------------------
  def cnc_add_badexits(self,tmplist):
    try:
      tmpexits = self.controller.get_conf('ExcludeExitNodes')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if len(tmpexits) > 0:
        tmpcurrexits = tmpexits.split(',')
      else:
        tmpcurrexits = []

    if type(tmplist) == None:
      outdata = None
    elif type(tmplist) == list:
      if len(tmplist) == 0 or ( len(tmplist) == 1 and tmplist[0] == '' ):
        outdata = None
      else:
        tmpbadentries = []
        for i in tmplist:
          if re.match(r'\{..\}$',i) and \
           not i.strip('{}') in self.digraphs.keys():
            tmpbadentries.append(i)
            debugout("\n\nERROR DIGRAPHY1\n\n") #XXX DEBUGGING
          elif not re.match(self.re_fingerprint, i) and \
           not re.match(self.re_validip, i) and \
           not re.match(r'\{..\}$',i) and \
           not re.match(self.re_validiprange, i):
            tmpbadentries.append(i)
        if len(tmpbadentries) > 0:
          self.logger.error( 'invalid command entries received: %s (should be fingerprint, ip or digraph)' % \
           ( ','.join(tmpbadentries) ) )
          return ValueError("invalid entries: %s" % ",".join(tmpbadentries))
        else:
          outdata = ','.join(tmplist + tmpcurrexits)
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    debugout("\n\nOUTDATA: %s: %s\n\n" % \
     ( type(outdata), outdata) ) #XXX DEBUGGING
    try:
      self.controller.set_conf('ExcludeExitNodes',outdata)
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      return True



  #---------------------------------------------
  def cnc_set_badexits(self,tmplist):
    debugout("\n\nSET BAD EXITS GOT: %s\n\n" % tmplist) #XXX DEBUGGING
    if type(tmplist) == None:
      outdata = None
    elif type(tmplist) == list:
      if len(tmplist) == 0 or ( len(tmplist) == 1 and tmplist[0] == '' ):
        outdata = None
      else:
        tmpbadentries = []
        for i in tmplist:
          if re.match(r'\{..\}$',i) and \
           not i.strip('{}') in self.digraphs.keys():
            tmpbadentries.append(i)
            debugout("\n\nERROR DIGRAPHY1\n\n") #XXX DEBUGGING
          elif not re.match(self.re_fingerprint, i) and \
           not re.match(self.re_validip, i) and \
           not re.match(r'\{..\}$',i) and \
           not re.match(self.re_validiprange, i):
            tmpbadentries.append(i)
        if len(tmpbadentries) > 0:
          self.logger.error( 'invalid command entries received: %s (should be fingerprint, ip or digraph)' % \
           ( ','.join(tmpbadentries) ) )
          return ValueError("invalid entries: %s" % ",".join(tmpbadentries))
        else:
          outdata = ','.join(tmplist)
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    debugout("\n\nOUTDATA: %s: %s\n\n" % \
     ( type(outdata), outdata) ) #XXX DEBUGGING
    try:
      self.controller.set_conf('ExcludeExitNodes',outdata)
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      return True

  #---------------------------------------------
  def cnc_get_badexits(self):
    try:
      tmpexits = self.controller.get_conf('ExcludeExitNodes')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if len(tmpexits) > 0:
        return tmpexits.split(',')
      else:
        return []
  #---------------------------------------------
  def cnc_get_entrynodes(self):
    #XXX TODO: keep track of this elsewhere??
    #XXX TODO: add more info, like port??
    entry_set = set()
    for i in self.controller.get_circuits():
      tmpitem = []
      tmpitem.append(i.path[0][0])
      tmpitem.append(i.path[0][1])
      try:
        tmpitem.append(self.controller.get_network_status( tmpitem[0]).address)
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        try:
          tmpitem.append( self.controller.get_info('ip-to-country/%s' % tmpitem[2]))
        except Exception, e:
          self.logger.exception(e)
          return e
        else:
          entry_set.add(tuple(tmpitem))
    return list(entry_set)

  #--------------------------------------------

  def cnc_set_hs(self,tmplist):
    if type(tmplist) == list and len(tmplist) >0:
      outdata = []
      for i in tmplist:
        if len(i) < 2 or type(i[0]) != str or type(i[1]) != str:
          return ValueError("invalid hs: %s" % str(i))
        if re.match(r'[1-9][0-9]{,4}$',i[1]):
          tmpport = i[1] + ' 127.0.0.1:' + i[1]
        elif re.match(r'[1-9][0-9]{,4} 127.0.0.1:[1-9][0-9]{,4}',i[1]):
          for j in re.sub(r'([0-9]+) +127.0.0.1:([0-9]+)$',r'\1 \2',i[1]).split(' '):
            try:
              if not 0 < int(j) < 65536:
                return ValueError("invalid port assignment: %s" % str(i[1]))
            except Exception, e:
              self.logger.exception(e)
              return e
            else:
              tmpport = i[1]
        else:
          return ValueError("invalid port: %s" % str(i[1]))
        tmpdir = self.atc_hsfolder
        if i[0] == '' or i[0] == None:
          while os.path.exists(tmpdir):
            tmpdir = ''
            for i in range(10):
              tmpdir += random.choice( string.ascii_letters )
            tmpdir = os.path.join(self.atc_hsfolder,tmpdir)
          try:
            os.makedirs(tmpdir)
          except Exception, e:
            self.logger.exception(e)
            continue
        elif not os.path.isdir(tmpdir):
          tmpdir = i[0]
          try:
            os.makedirs(tmpdir)
          except Exception, e:
            self.logger.exception(e)
            continue
        else:
          tmpdir = i[0]

        outdata.append(('HiddenServiceDir',tmpdir))
        outdata.append(('HiddenServicePort',tmpport))

        if len(i) >= 4:
          tmpurl = i[2]
          tmpkey = i[3]
          if re.match(self.re_onionaddr,tmpurl):
            with open(os.path.join(tmpdir,'hostname'),'w+') as filey:
              filey.write(tmpurl)
          else:
            self.logger.error(' invalid onion address at third element.')
            debugout('\n BAD ONION URL: %s\n' % tmpurl ) #XXX DEBUGGING
          if re.match( self.re_validrsakey, tmpkey):
            with open(os.path.join(tmpdir,'private_key'),'w+') as filey:
              filey.write(tmpkey)
          else:
            self.logger.error(' invalid private key at fourth element.')
            debugout('\n BAD PRIV KEY: %s\n' % tmpkey[:10] ) #XXX DEBUGGING
      #asdfx
      #if tmpdir in self.our_running_hidden_services.keys():
      #  self.logger.error(' hidden service detected with missing folder: %s' % \
      #   ( tmpdir ) )
      #  tmpdir = self.atctmpdir
      ### XXX ^^^  what??

      try:
        self.controller.set_options(outdata)
        self.controller.reset_conf('HiddenServiceOptions')
      except Exception, e:
        self.logger.exception(e)
        return e
    elif type(tmplist) == list and len(tmplist) == 0:
      self.controller.set_options( [('HiddenServiceDir',None), \
       ('HiddenServicePort',None)] )
    else:
      return TypeError( ' expected list, got %s' % ( type(tmplist) ) )




  #---------------------------------------------
  def cnc_add_hs(self,tmplist):
    try:
      tmphsdict= self.controller.get_conf_map('HiddenServiceOptions')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if tmphsdict.keys() == ['HiddenServiceOptions'] and \
       tmphsdict['HiddenServiceOptions'] == []:
        tmpconf = []
      else:
        tmpconf = []
        for x,y in zip(tmphsdict['HiddenServiceDir'],
         tmphsdict['HiddenServicePort']):
          tmpconf.append( ( x, y ) )



    if type(tmplist) == list and len(tmplist) >0:
      outdata = []
      for i in tmplist:
        if len(i) < 2 or type(i[0]) != str or type(i[1]) != str:
          return ValueError("invalid hs: %s" % str(i))
        if re.match(r'[1-9][0-9]{,4}$',i[1]):
          tmpport = i[1] + ' 127.0.0.1:' + i[1]
        elif re.match(r'[1-9][0-9]{,4} 127.0.0.1:[1-9][0-9]{,4}',i[1]):
          for j in re.sub(r'([0-9]+) +127.0.0.1:([0-9]+)$',r'\1 \2',i[1]).split(' '):
            try:
              if not 0 < int(j) < 65536:
                return ValueError("invalid port assignment: %s" % str(i[1]))
            except Exception, e:
              self.logger.exception(e)
              return e
            else:
              tmpport = i[1]
        else:
          return ValueError("invalid port: %s" % str(i[1]))
        tmpdir = self.atc_hsfolder
        if i[0] == '' or i[0] == None:
          while os.path.exists(tmpdir):
            tmpdir = ''
            for i in range(10):
              tmpdir += random.choice( string.ascii_letters )
            tmpdir = os.path.join(self.atc_hsfolder,tmpdir)
          try:
            os.makedirs(tmpdir)
          except Exception, e:
            self.logger.exception(e)
            continue
        elif not os.path.isdir(tmpdir):
          tmpdir = i[0]
          try:
            os.makedirs(tmpdir)
          except Exception, e:
            self.logger.exception(e)
            continue
        else:
          tmpdir = i[0]

        outdata.append(('HiddenServiceDir',tmpdir))
        outdata.append(('HiddenServicePort',tmpport))

        if len(i) >= 4:
          tmpurl = i[2]
          tmpkey = i[3]
          if re.match(self.re_onionaddr,tmpurl):
            with open(os.path.join(tmpdir,'hostname'),'w+') as filey:
              filey.write(tmpurl)
          else:
            self.logger.error(' invalid onion address at third element.')
            debugout('\n BAD ONION URL: %s\n' % tmpurl ) #XXX DEBUGGING
          if re.match( self.re_validrsakey, tmpkey):
            with open(os.path.join(tmpdir,'private_key'),'w+') as filey:
              filey.write(tmpkey)
          else:
            self.logger.error(' invalid private key at fourth element.')
            debugout('\n BAD PRIV KEY: %s\n' % tmpkey[:10] ) #XXX DEBUGGING
      #asdfx
      #if tmpdir in self.our_running_hidden_services.keys():
      #  self.logger.error(' hidden service detected with missing folder: %s' % \
      #   ( tmpdir ) )
      #  tmpdir = self.atctmpdir
      ### XXX ^^^  what??

      try:
        self.controller.set_options(outdata)
        self.controller.reset_conf('HiddenServiceOptions')
      except Exception, e:
        self.logger.exception(e)
        return e
    elif type(tmplist) == list and len(tmplist) == 0:
      self.controller.set_options( [('HiddenServiceDir',None), \
       ('HiddenServicePort',None)] )
    else:
      return TypeError( ' expected list, got %s' % ( type(tmplist) ) )





  #---------------------------------------------
  def cnc_get_hs(self):
    try:
      tmphsdict= self.controller.get_conf_map('HiddenServiceOptions')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if tmphsdict.keys() == ['HiddenServiceOptions'] and \
       tmphsdict['HiddenServiceOptions'] == []:
        tmpconf = []
      else:
        tmpconf = []
        for x,y in zip(tmphsdict['HiddenServiceDir'],
         tmphsdict['HiddenServicePort']):
          tmpconf.append( ( x, y ) )
    return tmpconf

  #---------------------------------------------

  def cnc_get_hsinfo(self,indata):
    #Get a two-element tuple with hiddenservice dir and/or port
    # (one of the two may be blank; 
    #   examples: ('/my/folder','1234 127.0.0.1:1234')
    #             ('','1234 127.0.0.1:1234')
    #             ('/my/folder','')
    #Returns a four-element list with folder, port, url and key (in that order)
    #If for some horrible reason, your input (for instance, a port and 
    # no foldername) produces more than one result, only the first will
    # be returned.
    #If there are no results (you only THOUGHT there was an active service),
    # this will return four elements of nothing ("None"-type)
    try:
      tmphsdict= self.controller.get_conf_map('HiddenServiceOptions')
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      if tmphsdict.keys() == ['HiddenServiceOptions'] and \
       tmphsdict['HiddenServiceOptions'] == []:
        tmpconf = []
      else:
        tmpconf = []
        for x,y in zip(tmphsdict['HiddenServiceDir'],
         tmphsdict['HiddenServicePort']):
          tmpconf.append( [ x, y , '', ''] )
    outputlist = [None,None,None,None]
    if ( indata[0] == None or indata[0] == '' ) and \
     ( indata[1] == None or indata[1] == '' ):
      #incase some maroon asks for a nothing,nothing wildcard, return nothing
      return outputlist
    #NOTE: the dirname from tor/stem may or may not have a trailing slash.
    #      We do not currently check that.
    #      Recommend getting the exact string from another query.
    #TODO: check?
    for i in tmpconf:
      if indata[0] == None or indata[0] == '' or indata[0] == i[0]:
        if indata[1] == None or indata[1] == '' or indata[1] == i[1]:
          outputlist[0] = i[0]
          outputlist[1] = i[1]
          try:
            with open(os.path.join(i[0],'hostname'),'r') as filey:
              outputlist[2] = filey.read().strip('\n')
          except Exception, e:
            self.logger.exception(e)
          try:
            with open(os.path.join(i[0],'private_key'),'r') as filey:
              outputlist[3] = filey.read()
          except Exception, e:
            self.logger.exception(e)
          return outputlist
    #No matches? return nothingness.
    return ValueError('no hs matches that criteria.')

        
  #---------------------------------------------
  def cnc_add_bridges(self,tmplist):
    try:
      tmpusingbridges = self.controller.get_conf('UseBridges')
    except Exception, e:
      self.logger.exception(e)
      return e
    if tmpusingbridges == '0':
      tmpbridges = []
    elif tmpusingbridges == '1':
      try:
        tmpbridges = self.controller.get_conf('Bridge',multiple=True)
      except Exception, e:
        self.logger.exception(e)
        return e

    #XXX OOPS need to GET first
    if type(tmplist) == None:
      outdata = []
    elif type(tmplist) == list:
      if len(tmplist) == 0:
        outdata = []
      else:
        tmpbadentries = []
        for i in tmplist:
          if not re.match(self.re_bridgeline_all, i):
            tmpbadentries.append(i)
        if len(tmpbadentries) > 0:
          self.logger.error('invalid command entries received: ' + \
           ','.join(tmpbadentries) + ' (should be fingerprint or ip)')
          return ValueError("invalid entries: %s" % ",".join(tmpbadentries))
        else:
          outdata = tmplist
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    try:
      self.controller.set_conf('Bridge', outdata + tmpbridges )
    except Exception, e:
      self.logger.exception(e)
      return e
    if tmpusingbridges == '0' and len(outdata+tmpbridges) > 0:
      try:
        self.controller.set_conf('UseBridges', '1' )
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        return True
    else:
      return True



  #---------------------------------------------
  def cnc_set_bridges(self,tmplist):
    try:
      tmpusingbridges = self.controller.get_conf('UseBridges')
    except Exception, e:
      self.logger.exception(e)
      return e

    if type(tmplist) == None:
      outdata = []
    elif type(tmplist) == list:
      if len(tmplist) == 0:
        try:
          self.controller.set_conf('UseBridges','0')
        except Exception, e:
          self.logger.exception(e)
          return e
        outdata = []
      else:
        tmpbadentries = []
        for i in tmplist:
          if not re.match(self.re_bridgeline_all, i):
            tmpbadentries.append(i)
        if len(tmpbadentries) > 0:
          self.logger.error('invalid command entries received: ' + \
           ','.join(tmpbadentries) + ' (should be fingerprint or ip)')
          return ValueError("invalid entries: %s" % ",".join(tmpbadentries))
        else:
          outdata = tmplist
    else:
      return TypeError("expected list, got %s" % str(type(tmplist)))
    try:
      self.controller.set_conf('Bridge',outdata)
    except Exception, e:
      self.logger.exception(e)
      return e
    if tmpusingbridges == '0' and len(outdata) > 0:
      try:
        self.controller.set_conf('UseBridges', '1' )
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        return True
    else:
      return True


  #---------------------------------------------
  def cnc_get_bridges(self):
    try:
      tmpusingbridges = self.controller.get_conf('UseBridges')
    except Exception, e:
      self.logger.exception(e)
      return e
    if tmpusingbridges == '0':
      return []
    try:
      tmpbridges = self.controller.get_conf('Bridge',multiple=True)
    except Exception, e:
      self.logger.exception(e)
      return e
    else:
      return tmpbridges
  #---------------------------------------------
  def cnc_set_signal(self,tmpstr):
    """Takes a string as argument, changes TOR connection accordingly.
    Accepted strings:
        'START'     (starts tor service)
        'STOP'      (stops tor service)
        'RESTART'   (restarts tor service)
        'RELOAD'    (reload the torrc/refresh tor conf)
        'NEWNYM'    (use new exit node)

    This should only be run from the command-n-control thread!
    """
    if type(tmpstr) != str and type(tmpstr) != unicode:
      self.logger.error( "set_signal: expected string or unicode, got %s" % \
       ( type(tmpstr) ) )
      return TypeError("expected string or unicode, got %s" % ( type(tmpstr) ) )
    elif tmpstr == 'NEWNYM':
      try:
        self.controller.signal(StemSignal.NEWNYM)
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        return True
    elif tmpstr == 'RELOAD':
      try:
        self.controller.signal(StemSignal.RELOAD)
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        return True
    elif tmpstr == 'START':
      self.logger.warning('attempting to start TOR...')
      self.tor_starter.stdin.write('1')
      return True #XXX check success on your own!
    elif tmpstr == 'RESTART':
      self.logger.warning('attempting to restart TOR...')
      self.tor_starter.stdin.write('2')
      return True #XXX check success on your own!
    elif tmpstr == 'STOP':
      self.logger.warning('attempting to stop TOR...')
      self.tor_starter.stdin.write('0')
      return True #XXX check success on your own!
    else:
      self.logger.error("received unknown signal type: %s" % str(tmpstr))
      return ValueError("unknown signal type: %s" % str(tmpstr))
  #---------------------------------------------
  def cnc_get_iplocation(self,tmpstr):
    if type(tmpstr) != str and type(tmpstr) != unicode:
      self.logger.error("get_iplocation: expected string or unicode, got %s" % type(tmpstr))
      return TypeError("expected string or unicode, got %s" % \
       ( type(tmpstr) ) )
    elif re.match( self.re_validip, tmpstr ):
      try:
        tmpip = self.controller.get_info('ip-to-country/%s' % tmpstr )
      except Exception, e:
        self.logger.exception(e)
        return e
      else:
        return tmpip
    else:
      self.logger.error("expected IP address, got: %s" % str(tmpstr))
      return ValueError("expected ip address, got %s" % str(tmpstr))
  #---------------------------------------------
  def cnc_get_supportedobfs(self):
    return [] #XXX we don't support obfs-proxy... yet...
  #---------------------------------------------
  def cnc_get_agentlogfiles(self):
    return self.loglist
  #---------------------------------------------
  def cnc_get_agentversion(self):
    return self.atc_agent_version
  #---------------------------------------------
  def cnc_get_broadcastresponses(self,*args):
    return False
  #---------------------------------------------
  def cnc_getallconfs(self,socket=None):
    debugout("\n\nCNC_GETALLCONFS\n\n") #XXX DEBUGGING
    return self.get_all_confs(socket)
      

  ###########################################################


  def build_new_circ_dict(self,socket = None):
    #circ_dict = dict with circuit ids as keys and the following
    #            elements in a list:
    #     [0]  signature (e.g.: '52F445C0CDAFE8A86B9AA05DB68A7D6B0AE49FE9' )
    #     [1]  nickname  (e.g.: 'My_exit_node')
    #     [2]  ip        (e.g.: '12.34.56.78')
    #     [3]  country digraph (e.g.: 'us')
    #     [4]  bandwidth **not implemented yet** (will be empty string, '')
    #
    #  additional keys:
    #          'last_circ': id of last circuit to have a data stream
    #          'last_circ_backup': complete listing (as seen above) of the
    #                              last circuit, in case circuit get torn down
    #                              before another stream starts...
    #          'internal_circs': ids of circuits that aren't for exiting

    tmpdict = {}
    tmpdict['internal_circs'] = []
    if 'last_circ' in self.circ_dict:
      tmpdict['last_circ'] = self.circ_dict['last_circ']
    else:
      tmpdict['last_circ'] = None
    if 'last_circ_backup' in self.circ_dict:
      tmpdict['last_circ_backup'] = self.circ_dict['last_circ_backup']
    else:
      tmpdict['last_circ_backup'] = []

    if self.bad_connects:
      tmpdict['bad_connect'] = True
    else:
      tmpdict['bad_connect'] = False

    for i in self.controller.get_circuits():
      if i.type == 'CIRC' and i.purpose == 'GENERAL' and i.status == 'BUILT' and not 'IS_INTERNAL' in i.build_flags and len(i.path) > 2 and len(i.path[-1]) > 1:
        #blank
        tmpdict[i.id] = ['','','','',{}]
        #exit signature
        tmpdict[i.id][0] = i.path[-1][0]
        #exit nick
        tmpdict[i.id][1] = i.path[-1][1]
        #exit ip
        try:
          tmpip = self.controller.get_network_status( tmpdict[i.id][0] ).address
        except Exception, e:
          self.logger.exception(e)
          tmpip='**ERROR**'
        tmpdict[i.id][2] = tmpip

        if re.match( self.re_validip, tmpdict[i.id][2] ):
          tmpdict[i.id][3] = self.controller.get_info('ip-to-country/%s' % tmpdict[i.id][2] )
        else:
          self.logger.critical('ERROR: bad input from circ_dict: cannot parse ip: %s' %  ( tmpdict[i.id][2] )  )
          self.logger.debug( 'circ.id: %s: %s\n' % ( i.id, tmpdict[i.id] ) )

        try:
          tmpbw = self.controller.get_network_status(tmpdict[i.id][0]).bandwidth
        except Exception:
          tmpbw = None
        if type(tmpbw) is int:
          tmpdict[i.id][4]['bandwidth'] = tmpbw
          # now get lowest bw determined from entire circuit
          maxbw = self.get_smallest_bw([j[0] for j in i.path])
          tmpdict[i.id][4]['maxbandwidth'] = maxbw
        else:
          debugout('\n\n tmpbw is not int ?!?!?! \n') #XXX DEBUGGING
          tmpdict[i.id][4]['bandwidth'] = None
      elif i.type == 'CIRC' and i.purpose == 'GENERAL' and i.status == 'BUILT' and 'IS_INTERNAL' in i.build_flags and len(i.path[-1]) > 1 :
        if not i.id in tmpdict['internal_circs']:
          tmpdict['internal_circs'].append(i.id)
    with self.lock_circ_dict:
      self.circ_dict = tmpdict
    if socket:
      self.bcast_notify(socket,'torcirc.exit',self.circ_dict)
 

  ############################################################

#  def notify_exit(self):
#    # gives the supplied output function the latest exit node in the following format:
#    #  [ <str:digraph>, <unicode:ip>, <str:nick>, <str:signature>, <list:<str: other digraphs>> ]
#    #  ex:  ['us', u'12.34.56.78', 'mytorserver', 'ABC123ABC123...', ['ch','de','us']]
#    outputz = []
#    #check for any stream **wait, why?**
#    #if len(self.curr_streams) > 0:
#    my_digraph = self.circ_dict[self.circ_dict['last_circ']][3]
#    my_ip =  self.circ_dict[self.circ_dict['last_circ']][2]
#    my_exitname = self.circ_dict[self.circ_dict['last_circ']][1]
#    my_exitsig = self.circ_dict[self.circ_dict['last_circ']][0]
#    other_exits = []
#    self.notifyexit(self.circ_dict)
#
  ###############################################################

  #################################################################

  def get_all_confs(self, bsocket = None):
    #take one argument, the socket to send the known settings to...
    debugout("\n\n*** xy1     GET_ALL_CONFS START\n\n") #XXX DEBUGGING
    if self.controller.is_authenticated() and self.controller.is_alive():
      tmpNodeCount = len( [ x for x in self.circ_dict.keys() \
       if re.match(r'^[0-9]{1,}$',x) ] )
      debugout("\n\n*** xy4     %s\n\n" % repr(self.circ_dict)) #XXX DEBUGGING
      self.bcast_notify(bsocket,'torcirc.exit',self.circ_dict)
    else:
      debugout("\n\n*** xy5     GET_ALL_CONFS: FAiL !!! 1\n\n") #XXX DEBUGGING
      self.bcast_notify(bsocket,'torstatus','Closed')
      return False
    #for i in ('UseBridges','ExitNodes','ExcludeExitNodes'):
    #  try:
    #    tmpconf = self.controller.get_conf(i)
    #  except Exception, e:
    #    self.logger.exception(e)
    #    continue
    #  else:
    #    self.notify_conf({ i : tmpconf.split(',') })
    try:
      if self.controller.get_conf('UseBridges') == '1':
        tmpconf = self.controller.get_conf('Bridge',multiple=True)
      else:
        tmpconf = []
    except Exception,e:
      self.logger.exception(e)
      return e
    else:
      self.bcast_notify(bsocket,'torconf.bridges',tmpconf)

    #asdfasdfasdfasdfasdf

    tmpconf = []
    try:
      tmphsdict= self.controller.get_conf_map('HiddenServiceOptions')
    except Exception, e:
      self.logger.exception(e)
    else:
      for x,y in zip(tmphsdict['HiddenServiceDir'],tmphsdict['HiddenServicePort']):
        tmpconf.append( ( x, y ) )
      self.bcast_notify(bsocket,'torconf.hs',tmpconf)

    try:
      tmpexits = self.controller.get_conf('ExitNodes')
    except Exception, e:
      self.logger.exception(e)
      self.bcast_notify(bsocket,'atc.error',e)
    else:
      debugout("\n\nBCAST_NOTIFY: goodexits: %s\n" % tmpexits ) #XXX DEBUGGING
      self.bcast_notify(bsocket,'torconf.goodexits',tmpexits.split(','))

    try:
      tmpexits = self.controller.get_conf('ExcludeExitNodes')
    except Exception, e:
      self.logger.exception(e)
      self.bcast_notify(bsocket,'atc.error',e)
    else:
      debugout("\n\nBCAST_NOTIFY: badexits: %s\n" % tmpexits ) #XXX DEBUGGING
      self.bcast_notify(bsocket,'torconf.badexits',tmpexits.split(','))


    #for i in ('Bridge',):
    #  try:
    #    tmpconf = self.controller.get_conf(i, multiple=True)
    #  except Exception, e:
    #    self.logger.exception(e)
    #    continue
    #  else:
    #    self.notify_conf({ i: tmpconf})
    return True

  ################################################################

  def reset_all_confs(self,socket):
    #NOTE: this does NOT actually reset the confs
    #      this is for the client to tell it there (should be)
    #      nothing for these settings because tor is down or
    #      resetting or something similar....

    #self.notify_conf({
    # 'UseBridges':'1',
    # 'Bridges':[],
    # 'ExitNodes':'',
    # 'ExcludeExitNodes':'',
    # 'HiddenServices':[],
    # })

    #self.notify_exit({
    # 'last_circ':self.circ_dict['last_circ'],
    # 'last_circ_backup':self.circ_dict['last_circ_backup'],
    # })
    tmpdict = {'last_circ':self.circ_dict['last_circ'], \
     'last_circ_backup':self.circ_dict['last_circ_backup'], \
     'bad_connect':True }
    #self.circ_dict = tmpdict
    self.bcast_notify(socket,'torconf.hs',[])
    self.bcast_notify(socket,'torconf.bridges',[])
    self.bcast_notify(socket,'torconf.goodexits',[])
    self.bcast_notify(socket,'torconf.badexits',[])
    self.bcast_notify(socket,'torcirc.exit', tmpdict)
    return True




  #################################################################

  def new_conf_event(self, my_event):
    #send a dict. each key has a list as its value
    #EVEN IF IT DOESN'T TAKE MULTIPLE VALUES!
    #example:
    #{'UseBridges':'1'}
    #becomes...
    #{'UseBridges':['1']}
    #...because some are multi, some not. AIN'T NOBODY GOT TIME FOR THAT!
    #
    #Hidden services are the only entry otherwise changed.
    #The key becomes 'HiddenServices' and the value
    # is a list of lists, each containing a dir/port pair
    #example: 
    # {'HiddenServicePort': '8888 127.0.0.1:8888', 
    #      'HiddenServiceDir': '/tmp/hs1/'}
    #becomes...
    # {'HiddenServices':[ [ '/tmp/hs1/', '8888 127.0.0.1:8888' ], ]
    #
    #Why?? BECAUSE I DON'T LIKE THE WAY STEM DOES IT!!!
    #########################self.notify_conf(my_event.config)

    #do we care about anything else here...??

    #XXX debugging...
    socket = self.zmq_event_sockets['conf']
    for i in my_event._parsed_content:
      if i[0] != '650':
        self.logger.error('*'*30 + 'Unidentified conf event received:\n %s \n' % \
         ( my_event._parsed_content ) )
    if not my_event._parsed_content[0] == ('650', '-', 'CONF_CHANGED') or \
     not my_event._parsed_content[-1] == ('650', ' ', 'OK') or \
     not len(my_event._parsed_content) >= 3:
      self.logger.error('*'*30 + 'Unidentified conf event received:\n %s \n' % \
       ( my_event._parsed_content ) )

    if 'ExitNodes' in my_event.config.keys():
      tmplist = my_event.config['ExitNodes'].split(',')
      self.bcast_notify(socket,'torconf.goodexits',tmplist)
    if 'ExcludeExitNodes' in my_event.config.keys():
      tmplist = my_event.config['ExcludeExitNodes'].split(',')
      debugout("\n\nNEW_CONF_EVENT: %s\n\n" % \
       my_event.config['ExcludeExitNodes'] ) #XXX DEBUGGING
      debugout("\n\nNEW_CONF_EVENT: TMPLIST: %s\n\n" % tmplist ) #XXX DEBUGGING
      self.bcast_notify(socket,'torconf.badexits',tmplist)

    if 'UseBridges' in my_event.config.keys():
      if my_event.config['UseBridges'] == '1':
        if 'Bridge' in my_event.config.keys():
          tmpbridgelist = []
          for i in range(len(my_event)):
            if re.match(r'^Bridge$',my_event[i]):
              tmpbridgelist = []
            elif re.match(r'^Bridge=',my_event[i]):
              tmpbridgelist.append(re.match('Bridge=(.*)', my_event[i]).groups[0])
          self.bcast_notify(socket,'torconf.bridges',tmpbridgelist)
        else:
          try:
            tmpbridgelist = self.controller.get_conf('Bridge',multiple=True)
          except Exception, e:
            self.logger.exception(e)
          else:
            self.bcast_notify(socket,'torconf.bridges',tmpbridgelist)
      else:
        self.bcast_notify(socket,'torconf.bridges',None)

    elif 'Bridge' in my_event.config.keys():
      tmpbridgelist = []
      for i in range(len(my_event)):
        if re.match(r'^Bridge$',my_event[i]):
          tmpbridgelist = []
        elif re.match(r'^Bridge=',my_event[i]):
          tmpbridgelist.append(re.sub(r'^Bridge=(.*)', r'\1', my_event[i]))
      try:
        if self.controller.get_conf('UseBridges') == '1':
          self.bcast_notify(socket,'torconf.bridges',tmpbridgelist)
        else:
          self.bcast_notify(socket,'torconf.bridges',[])
      except Exception,e:
        self.logger.exception(e)
    if 'HiddenServiceOptions' in my_event.config.keys():
      if my_event.config['HiddenServiceOptions'] == None:
        self.bcast_notify(socket,'torconf.hs',[])
      else:
        self.logger.error('*'*30 + 'Unidentified conf event received:\n %s \n' % \
         ( my_event._parsed_content ) )
    if 'HiddenServicePort' in my_event.config.keys() or \
     'HiddenServiceDir' in my_event.config.keys():
      #  tmphslist = []
      #  for i in range(len(my_event)):
      #    if re.match(r'^HiddenServiceDir=',my_event[i]):
      #      if re.match(r'HiddenServicePort=',my_event[i+1]):
      #        tmphslist.append( [ \
      #         re.sub(r'^HiddenServiceDir=(.*)', r'\1', my_event[i]),
      #         re.sub(r'HiddenServicePort=(.*)', r'\1', my_event[i+1]),
      #         ] )
      #####XXX XXX XXX the conf event WILL return fucked up: only showing one
      #####            of multiple hs's or showing the hs that is being
      #####            removed, etc... avoid the event entirely and re-hit
      #####            stem for the specific conf...
#asdfasdfasdf
      tmpconf = []
      try:
        tmphsdict= self.controller.get_conf_map('HiddenServiceOptions')
      except Exception, e:
        self.logger.exception(e)
      else:
        for x,y in zip(tmphsdict['HiddenServiceDir'],tmphsdict['HiddenServicePort']):
          tmpconf.append( ( x, y ) )
        self.bcast_notify(socket,'torconf.hs',tmpconf)

    tmpdict = {}
    alreadydone = ('HiddenServiceOptions','HiddenServicePort',
     'HiddenServiceDir','Bridge','UseBridges','ExitNodes','ExcludeExitNodes',)
    for i in my_event.config.keys():
      if i in alreadydone:
        continue
      else:
        if not i in tmpdict.keys():
          tmpdict[i] = []
        for j in my_event:
          if re.match( i + '=', j):
            tmpdict[i] = tmpdict[i] + re.sub(r'^[^=]*=(.*)',r'\1',j).split(',')
        #and for debugging/paranoia...
        #for k in self.controller.get_conf(i,multiple=True):
        #  if not k in tmpdict[i]:
        #    self.logger.error('entry not found in conf ' + str(i) + ': ' + \
        #     str(k) )
        #send up whatever conf...
    if tmpdict:
      self.bcast_notify(socket,'torconf.other',tmpdict)

  #################################################################

  def new_circ_event(self, my_event):
    ### possible stati for circuit events: LAUNCHED, EXTENDED,
    ###                                    BUILT, CLOSED, FAILED
    socket = self.zmq_event_sockets['circ']

    if my_event.status == 'BUILT' or my_event.status == 'EXTENDED':
      if self.bad_connects:
        with self.lock_bad_connects:
          self.bad_connects = 0
        with self.lock_circ_dict:
          self.circ_dict['bad_connect'] = False
          self.bcast_notify(socket,'torstatus','GoodConnect')
    elif my_event.status == 'FAILED':
      debugout('\ncirc FAIL 1 !!\n') #XXX DEBUGGING
      with self.lock_bad_connects:
        if self.bad_connects < 99: self.bad_connects += 1
      if ( self.bad_connects % 10 ) == 3:
        self.bcast_notify(socket,'torstatus','BadConnect')
        with self.lock_circ_dict:
          self.circ_dict['bad_connect'] = True

        ### XXX should we return here???
    ### ^^^ the only status not covered is "LAUNCHED" (which just indicates
    ###      that it's -trying- to make something new) and "CLOSED"...
        

    #with open('/tmp/eventtypes','a+') as filey:
    #  filey.write('\n%s\n' % my_event.status) #XXX DEBUGGING

    if my_event.status == 'FAILED': return

    self.logger.debug( 'new_circ: %s \n ' % my_event.__dict__ + '-'*30 )
    if my_event.purpose == 'GENERAL':
      if 'IS_INTERNAL' in my_event.build_flags:
        #internal circuits are weird, usually one-hop, circs that shouldn't
        # be able to exit anyways... Let's just ignore them for now...
        # They are not for HSs that we host....
        if my_event.status == 'BUILT':
          if not my_event.id in self.circ_dict['internal_circs']:
            self.circ_dict['internal_circs'].append(my_event.id)
            if len(self.circ_dict.keys()) > 30:
              self.logger.warning("more than 30 circuits on record. attempting purge.")
              self.build_new_circ_dict(socket)
              self.bcast_notify(socket,'torcirc.exit',self.circ_dict)
        elif my_event.status == 'CLOSED':
          if my_event.id in self.circ_dict['internal_circs']:
            self.circ_dict['internal_circs'].remove(my_event.id)
        self.logger.debug('SKIPPING INTERNAL CIRCUIT:\n %s \n' % \
         ( my_event._raw_content) )
        return 0
        ### end internal-only stuff

      elif my_event.status == 'CLOSED':
        #delete my_event.id from self.circ_dict
        if my_event.id in self.circ_dict.keys():
          del self.circ_dict[my_event.id]
        elif my_event in self.circ_dict['internal_circs']:
          self.circ_dict['internal_circs'].remove(my_event.id)
 
      elif my_event.status == 'BUILT':
        #not in dict, get new info
        with self.lock_circ_dict:
          self.circ_dict[my_event.id] = ['','','','',{}]
        #XXX ?? if self.controller.get_network_status( my_event.path[-1][0] ).status == 'BUILT' \
        if len(my_event.path) < 3 or len(my_event.path[-1]) < 2:
          self.logger.error('strange circuit event received:\n %s \n' % \
           ( my_event.__dict__ ) +'!'*30 )
          #TODO: more? (one-hop or malformed circuit)
        with self.lock_circ_dict:
          self.circ_dict[my_event.id][0] = my_event.path[-1][0]
          self.circ_dict[my_event.id][1] = my_event.path[-1][1]
          self.circ_dict[my_event.id][2] = self.controller.get_network_status( self.circ_dict[my_event.id][0] ).address


        #XXX XXX XXX

        if re.match( self.re_validip, self.circ_dict[my_event.id][2] ):
          try:
            tmpdigraph = self.controller.get_info('ip-to-country/%s' % self.circ_dict[my_event.id][2])
          except Exception, e:
            self.logger.critical('Error getting ip for %s : %s' % \
             ( my_event.id, self.circ_dict[my_event.id][2] ) )
            self.logger.debug(str(self.circ_dict[my_event.id]))
            self.logger.exception(e)
            #start over.
            self.build_new_circ_dict(socket)
            self.bcast_notify(socket,'torcirc.exit',self.circ_dict)
          #XXX self.notify_exit(self.circ_dict)
          if re.match( r'^[a-z?][a-z?]$', tmpdigraph ):
            with self.lock_circ_dict:
              self.circ_dict[my_event.id][3] = tmpdigraph
          else:
            self.logger.error('unknown input for country: %s' % ( tmpdigraph ) )
            self.logger.debug('-'*30 + '\n %s \n' % \
             ( self.circ_dict[my_event.id] ) +'!'*30 )
            with self.lock_circ_dict:
              self.circ_dict[my_event.id][3] = "??"
            #start over.
            #self.build_new_circ_dict()
        else:
          self.logger.critical('ERROR: bad input from circ_dict: cannot parse ip: %s' % ( self.circ_dict[my_event.id][2] ) )
          self.logger.debug( 'circ.id: %s: %s\n' % \
           ( my_event.id, self.circ_dict[my_event.id] ) + '!'*30 ) 
          #wtf. startover.
          self.build_new_circ_dict(socket)
          return
        #XXX XXX XXX
        try:
          tmpbw = self.controller.get_network_status(self.circ_dict[my_event.id][0]).bandwidth
        except Exception:
          tmpbw = None
        if type(tmpbw) is int:
          with self.lock_circ_dict:
            self.circ_dict[my_event.id][4]['bandwidth'] = tmpbw
            # now get lowest bw determined from entire circuit
            maxbw = self.get_smallest_bw([ j[0] for j in my_event.path ])
            self.circ_dict[my_event.id][4]['maxbandwidth'] = maxbw
        else:
          debugout('\n\n tmpbw is not int ?!?!?! 2\n') #XXX DEBUGGING
          tmpdict[i.id][4]['bandwidth'] = None
          with self.lock_circ_dict:
            self.circ_dict[my_event.id][4]['bandwidth'] = None
        self.bcast_notify(socket,'torcirc.exit',self.circ_dict)
        if len(self.circ_dict.keys()) > 30:
          self.logger.warning("more than 30 circuits on record. attempting purge.")
          self.build_new_circ_dict(socket)
        else:
          self.bcast_notify(socket,'torcirc.exit',self.circ_dict)


  ######################################################################
      
  def new_stream_event(self, my_event):
    ### type: (under 'status') NEW, SENTCONNECT, REMAP, SUCCEEDED, 
    ###         CLOSED or FAILED

    #with open('/tmp/streamtypes','a+') as filey:
    #  filey.write('\n%s\n' % my_event.status) #XXX DEBUGGING

    socket = self.zmq_event_sockets['stream']

    #XXX This is EXTREMELY verbose:
    #self.logger.debug('new_stream: %s\n\n' % ( my_event.__dict__ ) )

    newtorstatus = ''

    send_circ_dict = False

    debugout('// stream: %s %s %s //' % (my_event.id,my_event.status,my_event.circ_id)) #XXX DEBUGGING


    ## does the circuit making this stream appear in our circ_dict?
    ## slight chance of this happening if its a stream closing and then
    ## the circuit is immediately closed after that (race condition)
    if my_event.purpose == 'GENERAL' and \
     not 'IS_INTERNAL' in my_event.build_flags:
      if my_event.circ_id in self.circ_dict.keys():
        debugout('\n  stream oops circ_dict 1 !!! \n') #XXX DEBUGGING
        self.build_new_circ_dict(socket)
    elif my_event.purpose == 'GENERAL' and \
     'IS_INTERNAL' in my_event.build_flags:
      if my_event.circ_id in self.circ_dict.internal_circs:
        debugout('\n   stream oops circ_dict 2 !!! \n') #XXX DEBUGGING
        self.build_new_circ_dict(socket)

    if my_event.status == 'SENTCONNECT' or my_event.status == 'REMAP' or \
     my_event.status == 'DETACHED':
      ## don't care...
      return
    elif my_event.status == 'FAILED':
      if self.bad_connects >= 99:
        ### done told it 99 times already...
        pass
      else:
        with self.lock_bad_connects:
          self.bad_connects += 1
          if ( self.bad_connects % 10 ) == 3:
            ### say something at after 5, 15, 25, etc. failed attempts...
            newtorstatus = 'BadConnect'
            with self.lock_circ_dict:
              self.circ_dict['bad_connect'] = True
    elif my_event.status == 'CLOSED':
      ### could be the closing of a failed stream...
      pass
    elif my_event.status == 'SUCCEEDED':
      ### any success means we're back...
      newtorstatus = 'GoodStream'
      debugout('\n GOOD STREAM ! \n')

      if self.bad_connects:
        with self.lock_bad_connects:
          self.bad_connects = 0
      if self.circ_dict['bad_connect']:
        with self.lock_circ_dict:
          self.circ_dict['bad_connect'] = False
    else:
      debugout('\n%s\n' % my_event.status) #XXX DEBUGGING

    if my_event.id == None or my_event.circ_id == None:
      debugout('// blanked stream //')
      return
    elif my_event.status == 'SUCCEEDED' :
      #this should be the only one that doesn't immediately return:
      self.curr_streams.append(my_event.id)
    elif my_event.status == 'CLOSED':
      debugout('\n close stream: %s\n' % my_event.id ) #XXX DEBUGGING
      if my_event.id in self.curr_streams:
        self.curr_streams.remove( my_event.id )
      #if my_event.id in self.circ_dict.keys():
      #  del self.circ_dict[my_event.id]
      return
    else:
      #ignore statuses SENTCONNECT, REMAP, NEW, etc...
      return

    if my_event.status == 'SUCCEEDED':
      newtorstatus = 'GoodStream'
      debugout('\ntarget_address: %s=\n' % my_event.target_address ) #XXX DEBUGGING

      if re.match( r'^[a-z0-9]{16}\.onion(:[0-9]+)*$', \
       my_event.target_address ):
        #sending to onion address, do some debugging and nothing more...
        debugout('// is onion //') #XXX DEBUGGING
        debugout(repr(my_event))
        newtorstatus = 'GoodConnect'
        if my_event.circ_id in self.circ_dict.keys():
          debugout('// onion is normal circ //') #XXX DEBUGGING
        elif my_event.circ_id in self.circ_dict['internal_circs']:
          debugout('// onion is internal circ //') #XXX DEBUGGING
        else:
          self.logger.error('!' * 40 + 'Sending to onion address on unknown circuit')
          self.logger.error(str(my_event.__dict__))
          self.build_new_circ_dict(socket)
          ## since we are not exiting tor, send goodconnect instead
          ## of goodstream, showing healthy connections but not an outbound
          ## stream

      elif re.match( r'^[0-9]+\.[0-9]+.[0-9]+\.[0-9]+\.\$[A-F0-9]{40}\.exit(:[0-9]+)*$', my_event.target_address ):
        if my_event.circ_id in self.circ_dict.keys():
          debugout('// $exit is normal circ //') #XXX DEBUGGING
        elif my_event.circ_id in self.circ_dict['internal_circs']:
          debugout('// $exit is internal circ //') #XXX DEBUGGING
        else:
          self.logger.error('!' * 40 + 'Sending to internal exit address on unknown circuit')
          self.logger.error(str(my_event.__dict__))
          self.build_new_circ_dict(socket)

      elif my_event.circ_id != self.circ_dict['last_circ']:
        send_circ_dict = True
        #if re.match( r'^[0-9]+\.[0-9]+.[0-9]+\.[0-9]+\.\$[A-F0-9]{40}\.exit', \
        # my_event.target_address ) or \
        if my_event.circ_id in self.circ_dict.keys() :
          with self.lock_circ_dict:
            debugout('\nchange last_circ\n') #XXX DEBUGGING
            self.circ_dict['last_circ'] = my_event.circ_id
            self.circ_dict['last_circ_backup'] = \
             self.circ_dict[self.circ_dict['last_circ']]

        else:
          newtorstatus = ''
          self.logger.critical('!' * 40 + 'Event received for unidentified circuit!')
          self.logger.critical(str(my_event.__dict__))
          self.build_new_circ_dict(socket)
    if send_circ_dict:
      self.bcast_notify(socket,'torcirc.exit',self.circ_dict)
    if newtorstatus:
      self.bcast_notify(socket,'torstatus',newtorstatus)

  ######################################################################

  def new_status_change(self, _controller, _state, _timestamp):
    socket = self.zmq_event_sockets['status']
    self.logger.warning('new_status: %s \n %s \n' % ( _state, _timestamp ) \
     + '-'*30 )
    if _state.upper() == 'CLOSED':
      self._connected_to_tor = False
      self.logger.warning('lost connection to OR service')
      self.bcast_notify(socket,'torstatus','Closed')
      self.reset_all_confs(socket)
      while not self.shuttingdown:
        if self._connect_to_tor():
          self._connected_to_tor = True
          self.bcast_notify(socket,'torstatus','Init')
          self.logger.warning('re-established connection to OR service')
          break
        else:
          time.sleep(1)
      self.build_new_circ_dict(socket)
      self.get_all_confs(socket)
    elif _state.upper() == 'RESET':
      self.logger.warning('reset received')
      self._connected_to_tor = False
      self.reset_all_confs(socket)
      time.sleep(0.2)
      if not _controller.is_authenticated():
        self.bcast_notify(socket,'torstatus','Closed')
        self.logger.warning('lost connection to OR service')
        countx = 0
        while not self.shuttingdown:
          if self._connect_to_tor():
            self.bcast_notify(socket,'torstatus','Init')
            self._connected_to_tor = True
            break
          else:
            time.sleep(1)
      else:
        self.bcast_notify(socket,'torstatus','Reset')
      self.build_new_circ_dict(socket)
      self.get_all_confs(socket)
    elif _state.upper() == 'INIT':
      self._connected_to_tor = False
      self.logger.warning('TOR started')
      self.reset_all_confs(socket)
      while not self.shuttingdown:
        if self._connect_to_tor():
          self._connected_to_tor = True
          break
        else:
          time.sleep(1)
      self.build_new_circ_dict(socket)
      self.get_all_confs(socket)

  ################################################################

  def get_smallest_bw(self, siglist):
    if not type(siglist) == list:
      self.logger.error('get_smallest_bw expected list, got %s' % type(siglist))
      debugout('\n\nget_smallest_bw FAIL 1\n') #XXX DEBUGGING
    try:
      maxbw = self.controller.get_network_status(siglist[0]).bandwidth
    except Exception, e:
      self.logger.exception(e)
      debugout('\n\nget_smallest_bw FAIL 2\n') #XXX DEBUGGING
      maxbw = None
      return maxbw
    for i in siglist:
      debugout('\n%s\n' % i) #XXX DEBUGGING
      try:
        tmpnum = self.controller.get_network_status(i).bandwidth
      except Exception, e:
        self.logger.exception(e)
        debugout('\n\nget_smallest_bw FAIL 2\n') #XXX DEBUGGING
        maxbw = None
        return maxbw 
      debugout('%s\n' % tmpnum)
      if tmpnum < maxbw:
        maxbw = tmpnum
    debugout('maxbw: %d\n' % maxbw) #XXX DEBUGGING
    return maxbw
    

  ################################################################

  def get_hsurl(self,tmpdir):
    """Takes string as argument. String foldername of hidden service will be
    checked and return hidden service url as string (or bool False if error
    occurs."""
    debugout("\n\nGET_HSURL: START: %s\n" % tmpdir ) #XXX DEBUGGING
    if type(tmpdir) == unicode:
      tmpdir = str(tmpdir)
    if not type(tmpdir) == str:
      self.logger.error(" get_hsurl: expected string, got %s" % type(tmpdir) )
      return False
    if not os.path.isdir(tmpdir):
      self.logger.error(" get_hsurl: %s is not a folder." % tmpdir )
      return False
    tmpfile = os.path.join(tmpdir, 'hostname')
    if not os.path.isfile(tmpfile):
      self.logger.error(" get_hsurl: no hostname file found in %s" % tmpdir )
      return False
    try:
      with open(tmpfile,'r') as filey:
        tmpurl = filey.read().strip('\n')
    except Exception, e:
      self.logger.exception(e)
      return False
    else:
      if re.match(self.re_onionaddr,tmpurl):
        return tmpurl
      else:
        self.logger.error(" get_hsurl: invalid hostname returned from %s" % \
          ( tmpdir ) )
        self.oopsie()
        return False

  ###############################################################

  def LogFollow(self, filename, socket, label="log", allofit=True):
    try:
      logfile = open(filename,'r')
    except Exception, e:
      debugout('\n\nLOGFOLLOW: FAIL: 1: %s\n' % repr(e) ) #XXX DEBUGGING
      self.logger.exception(e)
      self.bcast_notify(socket,'agent.error',e)
      return False
    
    if not allofit: logfile.seek(0,2)
    self.bcast_notify(socket,label,"** reading file: %s" % filename )
    while not self.shuttingdown and self.bcast_torlog:
      line = logfile.readline()
      if line:
        self.bcast_notify(socket,label,line)
      else:
        time.sleep(0.2)
        continue
    self.bcast_notify(socket,label,"** read terminated for file: %s" % filename )

  ################################################################

  def monitor_async_reader(self,reader,command):
    assert hasattr(reader,'eof')
    assert hasattr(reader,'_queue')
    assert callable(command)
    while not self.shuttingdown and not reader.eof():
      while not self.shuttingdown and  not reader._queue.empty():
        line = reader._queue.get()
        command(line)
      time.sleep(0.2)

  ################################################################

  #def PipeFollow(self, pipes, socket, label="log",):
  #  pipelist = list(pipes)
  #  
  #  while not self.shuttingdown:
  #    line = 
  #    if line:
  #      self.bcast_notify(socket,label,line)
  #    else:
  #      time.sleep(0.2)
  #      continue
  #  self.bcast_notify(socket,label,"** read terminated for file: %s" % filename )


  #################################################################

  def checklockfile(self):
    #TODO: use the daemon and DaemonContext modules to do all this...
    #       and don't forget lockfile removal is currently in shutdownATC
    lockfilepath = self.atc_lockfilepath
    lockfilename = 'atc_agent.lock'
    #XXX TODO: ^^ should be pulled from a config file

    if self.logger and isinstance(self.logger, logging.Logger):
      error_out = self.logger.critical
      exception_out = self.logger.exception
    else:
      error_out = debugout
      exception_out = lambda x: debugout("Exception: %s" % repr(x))
    ## vvv checking that there's a folder for our folder to go into..
    if not os.path.isdir(os.path.split(lockfilepath)[0]):
      error_out("cannot create lockfile. System folder does not exist:%s" % str(os.path.split(lockfilepath)[0]))
      return False
    elif not os.path.isdir(lockfilepath):
      os.makedirs(lockfilepath)
    if os.path.isfile(os.path.join(lockfilepath,lockfilename)):
      tmpoutput = ''
      try:
        with open(os.path.join(lockfilepath,lockfilename), 'r') as filey:
          tmpoutput = filey.read()
      except Exception as e:
        exception_out(e)
      pids = re.findall(r'[0-9]+',tmpoutput)
      if not tmpoutput:
        pass
      elif len(pids) == 0:
        error_out('Malformed lockfile detected. Removing and continuing...')
        with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
          filey.write(str(os.getpid()))
      else:
        error_out('It appears that AnonTraCon agent is already running. Killing previous instances before continuing...')
        for i in pids:
          debugout('killing %s' % ( i ) )
          try:
            os.kill(int(i),signal.SIGKILL)
          except Exception as e:
            if not e.errno == 3:
              #look for anything but "No such process" error
              exception_out(e)
              self._shuterdown(1)
        
        time.sleep(1)
        #XXX do more killing and checking?
        with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
          filey.write(str(os.getpid()) + ' ')
    else:
      with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
        filey.write(str(os.getpid()) + ' ')
    return True

##################################################################

def testmain():
  return anontraconagent(logger=None)
 
###################################################################


if __name__ == "__main__":
  #sys.excepthook = anontraconagent.exceptyclosure()
  #logger = _create_log()
  standalone_atc = anontraconagent(logger=None)
