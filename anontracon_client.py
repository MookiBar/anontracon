#! /usr/bin/env python
from __future__ import print_function
import mimetypes
import os
import errno
import signal
import string
import json
import random
#TODO: move atc modules elsewhere to load from explicit path
import zmq
import re
import platform
import sys
import logging
import time
import subprocess
import importlib
import threading
## TODO: ^^^ find a mutex/lock mechanism within Qt...
#import stem.connection as StemConnection
#from stem.control import Signal as StemSignal
from PyQt4 import QtGui, QtCore
from threading import Thread

atc_folder = '/usr/share/anontracon'
sys.path.insert(0, atc_folder)

import anontracon_ui
import anontracon_utilities
import atcicons_rc
import freeflags_rc
from digraphs import digraphs


#XXX trap SIGINT, for debugging crappy code
signal.signal(signal.SIGINT, signal.SIG_DFL)

#def checklockfile():
#  #XXX   This shouldn't be needed any more. Only agent should have to lock.
#  #TODO: use the daemon and DaemonContext modules to do all this...
#  #       and don't forget lockfile removal is currently in shutdownATC
#  lockfilepath = os.path.join('/','var','lock','atc')
#  lockfilename = 'atc_main.lock'
#  #XXX ^^ should be pulled from a config file
#  if not os.path.isdir(os.path.split(lockfilepath)[0]):
#    QtGui.QMessageBox.warning(None, 'anontracon', 'cannot create lockfile. System folder does not exist: ' + str(os.path.split(lockfilepath)[0]), QtGui.QMessageBox.Ok)
#    return 0
#  elif not os.path.isdir(lockfilepath):
#    os.makedirs(lockfilepath)
#  if os.path.isfile(os.path.join(lockfilepath,lockfilename)):
#    tmpoutput = ''
#    try:
#      with open(os.path.join(lockfilepath,lockfilename), 'r') as filey:
#        tmpoutput = filey.read()
#    except Exception as e:
#      print(e.message)
#    pids = re.findall(r'[0-9]+',tmpoutput)
#    if not tmpoutput:
#      pass
#    elif len(pids) == 0:
#      QtGui.QMessageBox.warning(None, 'anontracon', 'Malformed lockfile detected. Removing and continuing...', QtGui.QMessageBox.Ok)
#      with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
#        filey.write(str(os.getpid()))
#    elif QtGui.QMessageBox.warning(None, 'anontracon', 'It appears that AnonTraCon is already running. Would you like to kill any previous instances and continue?', QtGui.QMessageBox.Ok,QtGui.QMessageBox.Cancel) == 1024:
#      for i in pids:
#        print('killing ' + str(i))
#        try:
#          os.kill(int(i),signal.SIGKILL)
#        except Exception as e:
#          print(e.message)
#      time.sleep(0.5)
#      #XXX do more killing and checking?
#      with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
#        filey.write(str(os.getpid()) + ' ')
#    else:
#      return False
#  else:
#    with open(os.path.join(lockfilepath,lockfilename), 'w+') as filey:
#      filey.write(str(os.getpid()) + ' ')    
#  return 1
 

def exceptyclosure(logfilename=None,logger=None,alertfunction=None):
  #this is a closure (for garbage collection reasons) that returns an
  # (uncalled) exception handler for the excepthook
  def exceptyhandler( ztype, zvalue, ztb):
    try:
      sys.stderr.write("uncaught exception!!!\n line {0}: {1}: {2}".format(ztb.tb_lineno,str(ztype),str(zvalue)))
      if logger:
        logger.critical('uncaught exception!!!\n line {0}: {1}: {2}'.format(ztb.tb_lineno,str(ztype),str(zvalue)))
      elif logfilename:
        with open(logfilename,'a+') as loggy:
          loggy.write("ERROR: uncaught exception!!! line {0}:{1}:{2}".format(ztb.tb_lineno,str(ztype),str(zvalue)))
      if alertfunction:
        alertfunction()
    except Exception, e:
      with open('/tmp/atc_error','a+') as filey:
        filey.write(time.ctime() + ': exception handling failure' + 
         '\n   ' + str(e.__repr__()) + '\n' )
    #pdb.pm()
  return exceptyhandler

  #######################################################################




class NewMainWindow(QtGui.QMainWindow):
  #subclass MainWindow to rewrite/prevent it closing
  genuisignal = QtCore.pyqtSignal(str)
  def __init__(self, parent=None):
    #QtGui.QMainWindow.__init__(self,parent)
    super(NewMainWindow, self).__init__(parent)
    self._allow_closing = False
  def closeEvent(self, eventy):
    if self._allow_closing:
      super(NewMainWindow, self).closeEvent(eventy)
    else:
      eventy.ignore()
      self.setVisible(False)

############################

class LogFollow(QtCore.QThread):
  #qthread for scraping logs
  def __init__(self, filename, signaly, allofit=True):
    QtCore.QThread.__init__(self)
    self.allofit = allofit
    self.filename = filename
    self.signaly = signaly
    ##XXX this is now left up to the signal, we just emit...
    ##  updating the widget from outside main thread may or
    ##  may not have been causing problems...
    #if type(self.widgey) == QtGui.QListWidget:
    #  self.widgtype = 1
    #elif type(self.widgey) == QtGui.QTextBrowser:
    #  self.widgtype = 2
    #else:
    #  self.widgtype = 0
    self.logfile = open(self.filename,'r')
  def __del__(self):
    self.wait()
  def run(self):
    if not self.allofit: self.logfile.seek(0,2)
    while True:
      line = self.logfile.readline()
      if not line:
        time.sleep(0.1)
        continue
      self.signaly.emit(line)


############# START LOGGING CONFIG ################################
def _create_log():
  #returns our default logger
  logger = logging.getLogger('atc_main_logger')
  logger.setLevel(logging.INFO)
  loggerfh = logging.FileHandler('/tmp/atc_client.log')
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

class SystemTrayIcon(QtGui.QSystemTrayIcon):
  #the mother ship...

  _confsignal = QtCore.pyqtSignal(list)
  _statussignal = QtCore.pyqtSignal(list)
  _exitsignal = QtCore.pyqtSignal(list)
  _torlogsignal = QtCore.pyqtSignal(str)
  _atclogsignal = QtCore.pyqtSignal(str)
  _disablesignal = QtCore.pyqtSignal()
  _enablesignal = QtCore.pyqtSignal()
  _clearsignal = QtCore.pyqtSignal()
  _popupsignal = QtCore.pyqtSignal(str)
  #_cncsignal = QtCore.pyqtSignal(list)
  _iconsignal = QtCore.pyqtSignal(str)
  _shutdownsignal = QtCore.pyqtSignal(int)
  _tooltipsignal = QtCore.pyqtSignal(str)

  _enable_debugoutput = True
  _debug_filename = '/tmp/atc_client.debug'

  #XXX should be getting this from a config file...
  torlogfilename='/var/log/tor/log'
  #atctmpdir = '/tmp/atctmp'
  atctmpdir = '/tmp'
  atc_runfolder = '/var/run/anontracon'
  error_header = '*ERROR*:'
  max_log_length = 10000
  ### ^^^ this is the max ascii CHARACTER length of the logs before truncation


  def __init__(self, parent=None, logger=None):
    self.shuttingdown = False
    self.lastIcon = '**NOTOR**'
    self.haveAuth = False
    self.haveCircs = False
    ### ^^^ helps us know when to change the icon...
    self.circ_dict = {'internal_circs':[], 'last_circ':None, \
     'last_circ_backup':[], 'bad_connect':True}
    self.debug('1')
    QtGui.QSystemTrayIcon.__init__(self, parent)
    #super(SystemTrayIcon, self).__init__(parent)
    self.mytitle = 'AnonTraCon'
    self.debug('2')
    if logger == None:
      self.logger = _create_log()
    else:
      self.logger = logger

    #INITIATE ALL LISTS, SETS, etc!
    #must be HERE, in init so they can get new ids but before anything else
    self.threadList = []
    self.threadLogList = []
    self.running_hidden_services = []
    ### ^^ includes ANY hidden services, a list of lists of Dir and Port:
    ###   e.g.  [['/a/dir/','123 127.0.0.1:123'],['/b/dir/','321 127.0.0.1']]
    self.our_running_hidden_services = {0:[],1:[]}
    ## ^^ 0:unknown services, 1:staged services (i.e. port assignments sent
    #                           off to the controller, and awaiting a response
    #     0,1 should alleviate any race conditions with the event listener.
    #   Anything that is fully established is listed with the dir as its key...
    #   e.g. { '/a/dir/':{
    self.unknown_hidden_services = {}
    ## ^^ will be like our_running_hidden_services except for hs's we did not
    #      start. Will only try to show dir, port, url. asdfx
    self.badConnect = True
    self.blockedCountries = set()
    self.blockedNodes = set()
    self.blockedOther = set()
    self.limitCountries = set()
    self.limitNodes = set()
    self.limitOther = set()
    self.bridges = set()
    self.allATCLogFilenames = []

    self.utilities = {}
    self.runningUtilities = {}



    self.debug('3')
    self._confsignal.connect(self.notifyConf)
    self._statussignal.connect(self.notifyStatus)
    self._exitsignal.connect(self.notifyExit)
    self._popupsignal.connect(self.trayPopup)
    #self._cncsignal.connect(self.cncSend)
    ## ^^ won't work because qt signal returns nothing...
    self._iconsignal.connect(self.change_icon)
    self._tooltipsignal.connect(self.set_tooltip)
    self._shutdownsignal.connect(lambda x: self.shutdownATC(x) )

    self.monkeynum = 0

    self.timer = QtCore.QTimer()
    self.notor_icon = QtGui.QIcon(":/atc_logos/atc_logo_small_slash.png")
    self.disconnected_icon = QtGui.QIcon(":/atc_logos/atc_logo_small_grey.png")
    self.connected_icon = QtGui.QIcon(":/atc_logos/atc_logo_small.png")
    self.error_icon = QtGui.QIcon(":/atc_logos/atc_logo_small_broken.png")

    self.setIcon(self.notor_icon)

    self.re_error_header = re.compile( re.escape(self.error_header) )
    self.re_bridgeline_all = re.compile(r'^ *(bridge +)?(obfs[1-9] +)?([0-9]{1,3}\.){3}[0-9]{1,3}:[1-9][0-9]* *( +([0-9A-Z]{4} ?){10})? *$')
    self.re_validip = re.compile(r'^(([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})\.){3}([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})$')
    #NOTE: further validation of ip-range must be done later...
    #    e.g. this will say that 192.168.255.255/8 is valid even though it
    #         doesn't make sense... (255s should be 0s)
    self.re_validiprange = re.compile(r'^(([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})\.){3}([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})/(4|8|12)$')
    self.re_onionaddr = re.compile(r'^[a-z0-9]{16}\.onion$')
    self.re_fingerprint = re.compile(r'^\s*([A-Z0-9]{4} ?){10}\s*$')
    self.re_validrsakey = re.compile(r'-----BEGIN RSA PRIVATE KEY-----\n([a-zA-Z0-9+/]{64}\n){12,20}[a-zA-Z0-9+/]{,64}={,4}\n-----END RSA PRIVATE KEY-----')
    #NOTE: ^^ this only works for tor's rsa keys. i.e.  with no email nor other
    #          identifying info and no password set...

    self.makeTrayMenus()

    self.activated.connect(self.showMainWindow)

    self.setToolTip('<b>' + self.mytitle + '</b>: <i>Initializing...</i>')
    self.MainWindow = NewMainWindow()
    self.ui = anontracon_ui.Ui_MainWindow()

    self.debug('4')
    #XXX XXX XXX  add LOCAL functions to the ui for its connection slots
    for i in [ 'addBlockCountries',
     'addBlockNode',
     'addTorBridges',
     'clearBlockedExits',
     'clearBridges',
     'clearExitLimits',
     'copyListWidget',
     'fill_country_widgets_list',
     'rebuildTorCircuits',
     'resetConfigPages',
     'resetOptionsPages',
     'resetServicesPages',
     'resetStatusPages',
     'restartTor',
     'restartTorQuick',
     'restoreATCConfig',
     'saveATCConfig',
     'addLimitCountry',
     'addLimitNode',
     'shutdownATC',
     'startHiddenServiceFile',
     'startBasicHiddenService',
     'startNewHiddenService',
     'startUtility',
     'stopHiddenService',
     'showHelpFAQ',
     ]:
      setattr(self.MainWindow,i,getattr(self,i))

    self.ui.setupUi(self.MainWindow)

    self._torlogsignal.connect(self.appendTORLog)
    self._atclogsignal.connect(self.appendATCLog)

    self._disablesignal.connect(self.disableEverything)
    self._enablesignal.connect(self.enableEverything)
    self._clearsignal.connect(self.clearEverything)


    #XXX XXX XXX
    #TODO: we gotta find a way to incorporate obfs...
    self.obfs_is_enabled = 0
    self.countryWidgetList = self.fill_country_widgets_list()

    for i in [ \
     self.ui.listWidgetConfigBlockCountrySet,
     self.ui.listWidgetLimitExitSetCountry,
     ]:
      tmpwidglist = self.fill_country_widgets_list()
      for j in tmpwidglist:
        i.addItem(j)
      del tmpwidglist

    self.buildFAQ()

    self._disablesignal.emit()
    #buttons should be off until the upcoming agent sends a status update

    self.debug('5')
    signal.signal(signal.SIGTERM, self._signalyhandler)
    signal.signal(signal.SIGINT, self._signalyhandler)
    signal.signal(signal.SIGUSR1, self._signalyhandler)
    signal.signal(signal.SIGUSR2, self._signalyhandler)

    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()

    for i in [ self.logger,]:
      for j in i.handlers:
        if type(j) == logging.FileHandler:
          try:
            tmpfilename = str(j.stream.name)
            self.allATCLogFilenames.append(tmpfilename)
            self.ui.textBrowserATCLog.append('**(reading log file: ' + tmpfilename + ')**\n')
          except Exception, e:
            self.logger.exception(e)
            self.oopsie()
          if os.path.isfile(tmpfilename):
            tmpatclogging = LogFollow(tmpfilename,self._atclogsignal,allofit=False) #XXX
            self.threadLogList.append(tmpatclogging)
            tmpatclogging.start()
          else:
            self.logger.error('attempting to get logging from ' + \
             'bad filename: %s' % ( tmpfilename ) )
            self.oopsie()

    #XXX XXX XXX this default should be from a config file...
    self.default_log_level = logging.INFO
    #self.agent.logger.setLevel(self.default_log_level)
    self.logger.setLevel(self.default_log_level)
    self.logger.warning('starting ATC client...')
    #self.agent.logger.info('starting logs')
    self.debug('10 a')
    ##without the sleep, I guess agent.controller wasn't ready for getAllConfs..
    #for i in range(20):
    #  time.sleep(0.2)
    ##XXX ^^ this CANNOT be qsleep or it'll HANG

    self.debug('11 a')
    # I'm following the FILE log instead of pulling log events from control
    # because if we lose contact with the controller, we still want to see
    # the log...
    #TODO: check we have the right filename for tor's log...
    #self.ui.textBrowserTORLog.clear()
    #self.ui.textBrowserTORLog.append('**(reading log file: ' + self.torlogfilename + ')**\n')
    self.debug('12 a')
    ### XXX XXX XXX WTF SHIT WE DON"T HAVE PERMISSIONS!!!!!!
    #if os.path.isfile(self.torlogfilename):
    #  self.debug('13')
    #  torlogging = LogFollow(self.torlogfilename,self._torlogsignal,allofit=True) #XXX
    #  self.threadLogList.append(torlogging)
    #  torlogging.start()
    #else:
    #  self.debug('14')
    #  self.ui.textBrowserTORLog.clear()
    #  self.ui.textBrowserTORLog.append('**LOG NOT AVAILABLE**')
    #  self.logger.error('could not access TOR log at "' + self.torlogfilename + '"')


    self.debug('7')

    for i in anontracon_utilities.__all__:
      try:
        self.utilities[i] = importlib.import_module('.'+i,'anontracon_utilities')
      except Exception, e:
        self.logger.exception(e)
        self.oopsie()
        continue
      if hasattr(self.utilities[i],'name') and hasattr(self.utilities[i],'description'):
        tmpname = str(getattr(self.utilities[i],'name'))
        tmpdescription = str(getattr(self.utilities[i],'description'))
        tmpitem = QtGui.QListWidgetItem()
        tmpitem.setText(tmpname + ': ' + tmpdescription)
        tmpitem._my_id=i
        #tmpitem.setIcon(QtGui.QIcon())
        self.ui.listWidgetUtilities.addItem(tmpitem)
    #self.ui.listWidgetUtilities.sort()
      else:
        self.logger.error(" loading utility without name and/or " + \
         "description: %s" % ( i ) )

    #make atctmpdir
    try:
      pass #XXX asdfasdfasdf
      #os.remove(self.atctmpdir)
    except OSError as e:
      if e.errno == errno.EISDIR:
        try:
          pass #XXX asdfasdfasdf
          #os.rmdir(self.atctmpdir)
        except Exception as f:
          self.logger.exception(f)
          self.logger.critical(' unable to create folder: ' + self.atctmpdir + \
           '. Old folder could not be removed.')
          self.oopsie()
      elif e.errno == errno.ENOENT:
        pass
      else:
        self.logger.exception(e)
        self.logger.critical(' unable to create folder: ' + self.atctmpdir)
        self.oopsie()
    try:
      pass #XXX asdfasdfasdf
      #os.makedirs(self.atctmpdir,0777)
      #TODO: ^^ change this after properly chown'ing things to match tor
      #XXX     This may or may not be permissive enough until then...
    except Exception as e:
      self.logger.exception(e)
      self.oopsie()

    self.debug('8')
    #XXX populate the list of services, starting with the default (basic)
    tmpitem = QtGui.QListWidgetItem()
    tmpitem.setText('Basic\n  We open the port to TOR, you do the rest.\n  -source: *none* (ATC default)-')
    tmpitem._my_id = 'basic'
    tmpitem.setIcon(QtGui.QIcon(':/Tango/face-monkey.png'))
    self.ui.listWidgetServicesNew.clear()
    self.ui.listWidgetServicesNew.addItem(tmpitem)
    QtGui.QApplication.processEvents()
    availableserviceslist = []
    #XXX TODO: actually make this.... something.... (asdfasdfasdf)
    for i in availableserviceslist:
      tmpitem = QtGui.QListWidgetItem()
      tmpitem.setText(i.name + '\n  ' + i.shortDescription + '\n  ' + i.source)
      tmpitem.setIcon(QtGui.QIcon(i.icon))
      tmpitem._my_id = i.name
      self.ui.listWidgetServicesNew.addItem(tmpitem)
      QtGui.QApplication.processEvents()

    self.debug('9')
    try:
      self.clipboard = app.clipboard()
    except NameError, e:
      self.clipboard = QtGui.QApplication.clipboard()
    except Exception, e:
      self.logger.exception(e)
      self.oopsie()

    self.MainWindow.resize(10,10)
    self.show()

    self.debug('10 b')
    self.send_lock = threading.Lock()
    self.zmq_context = zmq.Context()
    self.zmq_cnc_socket = self.zmq_context.socket(zmq.REQ)
    #self.zmq_socket_filename = os.path.join(self.atc_run_folder, str(self.pid))
    self.zmq_cnc_socket_filename = os.path.join(self.atc_runfolder, 'ATCCONTROL')

    ###XXX and finally, check for the agents sockets, die if not available
    ###     this one's a tricky balance between showing failure in the ui
    ###     and accidentally hanging the ui and actually shutting down in a
    ###     short amount of time.....
    ###    I know it looks dirty, but the first combination that did what I
    ###     want was what I stuck with.... 
    for i in range(100):
      QtGui.QApplication.processEvents()
    try:
      os.stat(self.zmq_cnc_socket_filename)
    except OSError:
      self.logger.critical("command-n-control socket not found. Must shutdown!")
      self.logger.error(" try starting/restarting the agent before starting the client.")
      self.shuttingdown = True
      self.debug("AGENT DOES NOT HAVE A SOCKET. ABORT.")
      #self._popupsignal.emit("AGENT NOT FOUND!\nShutting down in 15 seconds.")
      #self._iconsignal.emit('**ERROR**')
      self.change_icon('**ERROR**')
      self.trayPopup("AGENT NOT FOUND!\nShutting down in 15 seconds.")
      self.debug("kjlkjaldskfjladfjskasdjfldksf")
      for i in range(100):
        QtGui.QApplication.processEvents()
        time.sleep(0.01)
      time.sleep(0.1)
      for i in range(15):
        self.debug("Shutting down in %d seconds..." % ( 15 - i ) )
        QtGui.QApplication.processEvents()
        for i in range(10):
          time.sleep(0.1)
          QtGui.QApplication.processEvents()
        #self.qsleep(1)
      self._shutdownsignal.emit(1)
      for i in range(10):
        time.sleep(0.1)
    ###XXX same thing, but for the bcast socket.....
    for i in range(100):
      QtGui.QApplication.processEvents()
    try:
      os.stat(self.zmq_cnc_socket_filename)
    except OSError:
      self.logger.critical("broadcast socket not found. Must shutdown!")
      self.logger.error(" try starting/restarting the agent before starting the client.")
      self.shuttingdown = True
      self.debug("AGENT DOES NOT HAVE A SOCKET. ABORT.")
      #self._popupsignal.emit("AGENT NOT FOUND!\nShutting down in 15 seconds.")
      #self._iconsignal.emit('**ERROR**')
      self.change_icon('**ERROR**')
      self.trayPopup("AGENT NOT FOUND!\nShutting down in 15 seconds.")
      for i in range(100):
        QtGui.QApplication.processEvents()
        time.sleep(0.01)
      time.sleep(0.1)
      for i in range(15):
        self.debug("Shutting down in %d seconds..." % ( 15 - i ) )
        QtGui.QApplication.processEvents()
        for i in range(10):
          time.sleep(0.1)
          QtGui.QApplication.processEvents()
        #self.qsleep(1)
      self._shutdownsignal.emit(1)
      for i in range(10):
        time.sleep(0.1)


   
    #NOTE: we will not be setting our own ID at this time...
    #self.zmq_control_socket.setsockopt(zmq.IDENTITY,'CLIENT1')
    self.zmq_cnc_socket.connect("ipc://" + self.zmq_cnc_socket_filename)
    #TODO: RESTRICT ACCESS TO THAT SOCKET!
    self.zmq_cnc_socket.poll(1) #TODO: WHAT WAS THE POLLING BUG?!?!?!

    self.zmq_bcast_socket = self.zmq_context.socket(zmq.SUB)
    self.zmq_bcast_socket_filename = os.path.join(self.atc_runfolder, 'ATCBROADCAST')
    self.zmq_bcast_socket.connect("ipc://" + self.zmq_bcast_socket_filename)
    self.zmq_bcast_socket.setsockopt(zmq.SUBSCRIBE, b'')


    self.debug('11 b')
    self.zmq_thread_subscribe = self.startThread(self.zmq_recv_func)

    self.debug('12 b')

    self.logger.info("attempting to connect to agent")
    try:
      if self.checkHaveAuth():
        self.debug("GOT AUTH") #XXX DEBUGGING
        self.logger.info("connected to agent; agent authenticated")
      else:
        self.debug("NO AUTH") #XXX DEBUGGING
        self.logger.error("attempting to connect to agent; not authenticated")
        self.oopsie()
    except Exception, e:
      self.logger.exception(e)
      self.oopsie()
    tmprep = self.cncSend('get_agentlogfiles')
    if isinstance(tmprep,Exception):
      self.logger.error('unable to get agent log files.')
      self.oopsie()
    elif type(tmprep) == list:
      for i in tmprep:
        tmpfilename = i
        self.allATCLogFilenames.append(tmpfilename)
        self.ui.textBrowserATCLog.append('**(reading log file: %s )**\n' % \
         ( tmpfilename ) )
        if os.path.isfile(tmpfilename):
          tmpatclogging = LogFollow( tmpfilename, self._atclogsignal, \
           allofit=False) #XXX
          self.threadLogList.append(tmpatclogging)
          tmpatclogging.start()
        else:
          self.logger.error('attempting to get logging from bad filename: ' + tmpfilename)
          self.oopsie()
    else:
      self.logger.error('received unknown data-type for agent loggers: %s' % \
       type(tmprep) )
      self.oopsie()
    if not self.cncSend('set_bcasttorlog',False):
      self._torlogsignal.emit('** ERROR! TOR log signal could not be reset **')
    if not self.cncSend('set_bcasttorlog',True):
      self._torlogsignal.emit('** ERROR! TOR log could not be opened **')
    tmprep = self.cncSend('get_allconfs') #XXX asdfasdfasdfx
    self.logger.info("init completed")
    self.debug("INIT DONE") #XXX DEBUGGING



#  class RightClickMenu(QtGui.QMenu):
#    def __init__(self, parent=None):
#      QtGui.QMenu.__init__(self, "Edit", parent)
#  
#      tmpicon = QtGui.QIcon.fromTheme("edit-cut")
#      menu_settings = self.addAction(QtGui.QAction(tmpicon, self.tr("Settings..."), self))
#  
#      tmpicon = QtGui.QIcon.fromTheme("edit-copy")
#      menu_about = self.addAction(QtGui.QAction(tmpicon, self.tr("About..."), self))
#  
#      tmpicon = QtGui.QIcon.fromTheme("edit-paste")
#      menu_quit = self.addAction(QtGui.QAction(tmpicon, self.tr("Quit"), self))
#      #self.connect(menu_quit, SIGNAL('triggered()'), self.
##      menu_quit.triggered.connect(
#
#      tmpicon = None

  #######################################################################

  def _signalyhandler(self, zsignal, zframe):
    """Takes a signal (ex: SIGHUP) and a frame as argument."""
    if zsignal == 1 :
      self.logger.info('SIGHUP received')
    elif zsignal == 2 :
      self.logger.info('SIGINT received')
      self.shutdownATC(zsignal)
    elif zsignal == 3 :
      self.logger.info('SIGQUIT received')
      self.shutdownATC(zsignal)
    elif zsignal == 15 :
      self.logger.info('SIGTERM received')
      self.shutdownATC(zsignal)
    elif zsignal == 11 :
      self.logger.info('SIGSEGV received')
      self.logger.info('-' * 30 + '\n' + str(dir(zframe)))
    elif zsignal == 10 :
      self.logger.info('SIGUSR1 received')
    elif zsignal == 11 :
      self.logger.info('SIGUSR2 received')

  #########################################

  def debug(self, tmpstr):
    if self._enable_debugoutput:
      if self._debug_filename:
        with open(self._debug_filename,'a+') as filey:
          filey.write('%s\n' % tmpstr )
      else:
        sys.stderr.write('%s\n' % tmpstr)

  #########################################

  def startThread(self,funcy,*kwargs):
    """Takes a function object as argument, returns a thread running
    that function."""
    self.debug('starting new thread')
    self.logger.warning('starting new thread')
    if not hasattr(funcy,'__call__'):
      self.debug('stx')
      self.logger.error('tried starting a thread with a function that cannot '
        + 'be called:\n' + str(funcy))
      self.oopsie()
      return 0
    tmpthread = QtCore.QThread()
    self.debug('st1')
    tmpthread.run = funcy
    self.debug('st2')
    self.threadList.append(tmpthread)
    tmpthread.finished.connect(self.removeThread)
    tmpthread.start()
    self.logger.warning('thread started')
    self.debug('finished thread')
    return tmpthread
    
  #########################################

  def removeThread(self):
    tmpthread = self.sender()
    while not tmpthread.isFinished():
      self.qsleep(0.5)
    self.threadList.remove(tmpthread)

  #########################################

  def cncSend(self,intype,indata=''):
    """send a request over zmq to command-n-control socket, 
    get response/data back. Takes two args: intype: a string identifier,
    indata: a python object.  ARGUMENTS SHOULD NOT BE JSON OBJECTS!"""
    self.debug("cncSend START: intype: %s indata: %s" % \
     (intype,indata) ) #XXX DEBUGGING
    while self.zmq_cnc_socket.poll(1):
      tmpleftovers = self.zmq_cnc_socket.recv_multipart()
      self.logger.error("leftover data on cnc queue: %s" % tmpleftovers)
      #self.oopsie()
      self.debug("WOOPSIE leftovers") #XXX DEBUGGING
    if indata == '':
      jindata = indata
    else:
      try:
        jindata = json.dumps(indata)
      except Exception, e:
        self.logger.exception(e)
        self.oopsie()
        return False
    self.debug("cncSend: JINDATA: %s" % jindata ) #XXX DEBUGGING
    with self.send_lock:
      #XXX ^^ not very qt, but how else to make zmq socketry thread-safe?
      #XXX
      try:
        self.zmq_cnc_socket.send_multipart([intype,jindata])
      except Exception, e:
        self.logger.exception(e)
        self.oopsie()
        return False
      else:
        tmpx = False
        while not self.zmq_cnc_socket.poll(1000):
          if not tmpx:
            self.logger.error(" command-n-control socket not responding.")
            self.oopsie()
            tmpx = True
          self.qsleep(0.1)
        ##TODO: ^^ eventually fail out??
        tmprep = self.zmq_cnc_socket.recv_multipart()
        if tmprep[0] == intype:
          if re.match(self.re_error_header,tmprep[1]):
            self.logger.error("cnc request: %s returned failure: %s" % \
            ( intype, tmprep[1] ) )
            self.oopsie()
            return False
          try:
            tmprepdata = json.loads(tmprep[1])
          except Exception, f:
            self.logger.exception(f)
            self.oopsie()
          else:
            return tmprepdata

  #########################################

  def zmq_recv_func(self):
    """Intended to run in its own thread, will poll the broadcast socket
    for new data and, when received, will send events to the ui."""
    #   This function receives zmq broadcasts and sends them to their places
    #XXX TODO THIS NEEDS A POLLER! NOT RECEIVING FOREVER!
    while not self.shuttingdown:
      try:
        incoming = self.zmq_bcast_socket.recv_multipart()
      except Exception, e:
        self.logger.exception(e)
        self.oopsie()
      else:
        if incoming[0] != "tor.log": self.debug("ZMQ_RECV_FUNC: RECVD: %s" % incoming ) #XXX DEBUGGING
        if type(incoming) == str:
          if incoming == 'XXX':
            pass
          else:
            self.logger.error('received unidentified string: %s' % incoming)
            self.oopsie()
        elif type(incoming) == list:
          isException = False
          if re.match(self.re_error_header,incoming[1]):
            isException = True
          else:
            try:
              tmpdata = json.loads(incoming[1])
            except Exception, e:
              self.logger.exception(e)
              self.oopsie()
              continue
          
          if incoming[0] == 'atc.shutdown':
            self._disablesignal.emit()
            self._iconsignal.emit('**ERROR**')
            self.logger.warning('ATC agent has shutdown. Client will also ' + \
             'shut down in 15 seconds.')
            self._popupsignal.emit('ATC agent has stopped!\n' + \
             ' Forcing shutdown in 15 seconds.' )
            for i in range(15):
              self.debug( "shutting down in %i seconds" % ( 15 - i ) )
              for j in range(10):
                time.sleep(0.1)
            self._shutdownsignal.emit(1)
            return
          if incoming[0] == 'atc.error' or isException:
            self._atclogsignal("%s: %s" % ( incoming[0], incoming[1] ) )
            continue
          if incoming[0] == 'tor.log':
            self._torlogsignal.emit(incoming[1])
            continue
          elif incoming[0] == 'torstatus':
            tmpsignaller = self._statussignal 
          elif incoming[0] == 'torconf.bridges' \
           or incoming[0] == 'torconf.hs' \
           or incoming[0] == 'torconf.goodexits' \
           or incoming[0] == 'torconf.badexits' \
           or incoming[0] == 'torconf.other':
            tmpsignaller = self._confsignal
          elif incoming[0] == 'torcirc.exit':
            tmpsignaller = self._exitsignal
          else:
            self.logger.error('unknown broadcast type: %s' % incoming[0])
            self.oopsie()
            continue
          tmpsignaller.emit([incoming[0],tmpdata])


#        elif type(incoming) == dict:
#          try:
#            tmptype = incoming.pop('type')
#          except Exception, e:
#            self.logger.exception(e)
#            self.logger.error('received malformed imput from agent')
#          else:
#            if tmptype == 'conf':
#              self._confsignal.emit(incoming)
#            elif tmptype == 'status':
#              self._statussignal.emit(incoming['status'])
#            elif tmptype == 'exit':
#              self._exitsignal.emit(incoming)

        else:
          self.logger.error(str(e))
          self.logger.error("unknown type: %s" % str(type(incoming)))
          self.oopsie()
    self.zmq_bcast_socket.close()
    #asdfasdfasdf XXX


  #########################################
  #XXX
  def qsleep(self,num=1):
    """Timed idle that allows the processing of Qt events to occur.
    Will sleep for at least one tenth of one second.
    Takes one argument, an integer/float/number for the number of seconds
    to idle. Function will take AT LEAST that much time (depending on how
    long any Qt events take to process) and may hang if a Qt event hangs."""
    num = num * 10
    while num > 0:
      QtGui.QApplication.processEvents()
      time.sleep(0.1)
    #XXX experimental: try to block a function while not blocking qt events
    #      this probably causes extra strain on the cpu....
    #self.debug('qsleep ' + str(num) + '')
    #tmpthread = QtCore.QThread()
    #tmpthread.run = lambda: time.sleep(num)
    #tmpthread.start()
    #tmpthread.wait()

  ########################### UI FUNCS ##################################

  def fill_country_widgets_list(self):
    tmplisty = []
    tmpwidgetlist = []
    for i in digraphs.keys():
      if i == '??': continue
      tmplisty.append([digraphs[i],i,":/flags_small/flag-" + i + ".png"])
    for i in tmplisty:
      tmpitem = QtGui.QListWidgetItem()
      tmpitem.setText(i[0] + " (" + i[1] + ")" )
      tmpitem._my_id=i[1]
      tmpitem.setIcon(QtGui.QIcon(i[2]))
      tmpwidgetlist.append(tmpitem)
    tmpwidgetlist.sort()
    return tmpwidgetlist
  
  def resetConfigPages(self):
    for i in [ \
     self.ui.plainTextEditBridges,
     self.ui.plainTextEditLimitExitSetNodes,
     self.ui.plainTextEditConfigBlockNodeSet,
     ]:
      i.clear()
    for i in [ \
     self.ui.buttonGroupConfigBlock,
     self.ui.buttonGroupConfigLimit,
     self.ui.buttonGroupBridges,
     ]:
      i.setExclusive(False)
    for i in [ \
     self.ui.radioButtonConfigBlockClear,
     self.ui.radioButtonConfigBlockCountry,
     self.ui.radioButtonConfigBlockNode,
     self.ui.radioButtonConfigLimitCountry,
     self.ui.radioButtonConfigLimitNode,
     self.ui.radioButtonConfigLimitClear,
     self.ui.radioButtonAddBridges, 
     self.ui.radioButtonClearBridges, 
     ]:
      i.setChecked(False)
    for i in [ \
     self.ui.buttonGroupConfigBlock,
     self.ui.buttonGroupConfigLimit,
     self.ui.buttonGroupBridges,
     ]:
      i.setExclusive(True)
    for i in [ \
     self.ui.listWidgetLimitExitSetCountry,
     self.ui.listWidgetConfigBlockCountrySet,
     ]:
      for j in i.selectedItems():
        j.setSelected(False)
    self.ui.stackedWidgetLimitExitSet.setCurrentWidget(self.ui.pageLimitExitSetBlank)
    self.ui.stackedWidgetConfigBlockSet.setCurrentWidget(self.ui.pageConfigBlockBlank)
    self.ui.stackedWidgetConfig.setCurrentWidget(self.ui.pageConfigMain)
    self.ui.stackedWidgetBridges.setCurrentWidget(self.ui.pageAddClearBridgesBlank)
  
  def resetServicesPages(self):
    for i in [ \
     self.ui.lineEditServicesStart,
     ]:
      i.clear()
    self.ui.stackedWidgetServices.setCurrentWidget(self.ui.pageServicesMain)
    self.ui.spinBoxServicesNewBasic.setValue(0)
  
  def resetOptionsPages(self):
    for i in [ \
     self.ui.buttonGroupOptionsSaveRestore,
     ]:
      i.setExclusive(False)
    for i in [ \
     self.ui.radioButtonOptionsSaveConfig,
     self.ui.radioButtonOptionsRestoreConfig,
     ]:
      i.setChecked(False)
    for i in [ \
     self.ui.buttonGroupOptionsSaveRestore,
     ]:
      i.setExclusive(True)
    for i in [ \
     self.ui.lineEditOptionsSaveConfig,
     self.ui.lineEditOptionsRestoreConfig,
     ]:
      i.clear()
    for i in [ \
     self.ui.listWidgetUtilities,
     ]:
      for j in i.selectedItems():
        j.setSelected(False)
    self.ui.stackedWidgetOptionsSaveRestoreConfig.setCurrentWidget(self.ui.pageSaveRestoreConfigBlank)
    self.ui.stackedWidgetOptions.setCurrentWidget(self.ui.pageOptionsMain)
 
  def resetStatusPages(self):
    self.ui.lineEditOptionsSaveConfig.clear()
    self.ui.lineEditOptionsRestoreConfig.clear()
    for i in [ \
     self.ui.buttonGroupRestartTor,
     ]:
      i.setExclusive(False)
    for i in [ \
     self.ui.radioButtonRestartTorFull,
     self.ui.radioButtonRestartTorQuick,
     ]:
      i.setChecked(False)
    for i in [ \
     self.ui.buttonGroupRestartTor,
     ]:
      i.setExclusive(True)
    self.ui.stackedWidgetStatus.setCurrentWidget(self.ui.pageStatusMain)
    self.ui.stackedWidgetRestartTor.setCurrentWidget(self.ui.pageRestartTorBlank)

#XXX  

  def copyListWidget(self,widgey):
    """asdfasdfasdf"""
    tmptext = ''
    if not type(widgey) == QtGui.QListWidget or not widgey.isEnabled():
      return
    else:
      for i in range(widgey.count()):
        tmptext += str(widgey.item(i).text()) + '\n'
        self.clipboard.setText(tmptext)
      del tmptext
  
  #############################

  def addLimitCountry(self):
    """Add country list from ui to list of allowed exits."""
    if len(self.ui.listWidgetLimitExitSetCountry.selectedItems()) == 0: return
    self._disablesignal.emit()
    if ( len(self.limitCountries) + len(self.limitNodes) ) != 0:
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'You are about to set TOR to only use certain exits. This can SEVERLY limit it\'s connectivity! TOR may ignore these settings if they are not feasible.\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
      elif QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'Be sure, if the exits that you have chosen are not available, TOR will either lose connectivity or ignore your settings! Make sure to include as many exits as possible!\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
    tmpallblocks = []
    tmpcountries = []
    tmpcountries = ['{' + i + '}' for i in self.limitCountries ]
    for i in self.ui.listWidgetLimitExitSetCountry.selectedItems():
      tmpcountries.append('{' + i._my_id + '}')
      i.setSelected(False) 
    if not self.cncSend('add_goodexits', tmpcountries + list(self.limitNodes) ):
      self.logger.error('unable to set exit nodes.')
      self.oopsie()
    self.timer.singleShot(10000,self._enablesignal.emit)
    self.resetConfigPages()

  ###########################

  def addLimitNode(self):
    """Add exit nodes from ui to list of allowed exits."""
    if not re.search(r'\S',self.ui.plainTextEditLimitExitSetNodes.toPlainText(),re.MULTILINE):
      return
    self._disablesignal.emit()
    if ( len(self.limitCountries) + len(self.limitNodes) ) == 0:
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'You are about to set TOR to only use certain exits. This can SEVERLY limit it\' connectivity (or leave you with no connectivity at all)!\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
      elif QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'Be sure, if the exits that you have chosen do not exist, you will not be able to connect! If you have not chosen enough exits (or they become unavailable) you will lose your connection!\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
    self.debug("block the fingerprint in lineEditConfigBlockNodeSet")
    tmpallblocks = []
    tmpnodes = []
    tmpbadentries = []
    tmpentries = str(self.ui.plainTextEditLimitExitSetNodes.toPlainText()).split('\n')
    for i in range(len(tmpentries)):
      tmpentry= re.sub(r'\s',r'', tmpentries[i] )
      if re.match(self.re_fingerprint, tmpentry):
        tmpnodes.append( tmpentry )
      elif re.match(self.re_validip, tmpentry):
        tmpnodes.append( tmpentry )
      elif re.match(self.re_validiprange, tmpentry ):
        if re.match(r'.*/4$|.*/8$|.*/12$', tmpentry ):
          tmpiter = re.sub(r'.*/([1248])+$',r'\1', tmpentry)
          try:
            tmpiter = str( int(tmpiter) / 4 )
          except Exception, e:
            self.logger.exception(e)
            tmpbadentries.append(tmpentries[i])
            continue
          else:
            if re.match(self.re_validip, re.sub(r'(.*)/[0-9]+$',r'\1',tmpentry)) and re.match(r'.*(\.0){' + tmpiter + '}/[0-9]+$', tmpentry):
              tmpnodes.append( tmpentry )
            else:
              tmpbadentries.append(tmpentries[i]) 
        else:
          tmpbadentries.append(tmpentries[i])
          continue
      elif re.match(r'.*\S', tmpentries[i]):
        tmpbadentries.append(tmpentries[i])

    if len(tmpbadentries) > 0:
      QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'Only the fingerprints or IP addresses of TOR nodes are allowed. The fingerprint is a 40-character cryptographically-hashed string.\n\nThe following invalid lines were entered:\n' + '\n'.join(tmpbadentries), QtGui.QMessageBox.Ok)
      self._enablesignal.emit()
      return
    elif len(tmpnodes) > 0:
      tmpnodes = list(self.limitNodes) + tmpnodes
      #and now this, just to add brackets {}....
      tmpcountries = []
      for i in self.limitCountries:
        tmpcountries.append( re.sub(r'(..)',r'{\1}', i) )
      if not self.cncSend('add_goodexits', tmpcountries + tmpnodes ):
        self.logger.error('unable to set exit nodes.')
        self.oopsie()
    self.timer.singleShot(10000,self._enablesignal.emit)
    self.resetConfigPages()

  ##########################

  def clearExitLimits(self):
    """Clear any settings for limiting TOR exits."""
    self._disablesignal.emit()
    if not self.cncSend('set_goodexits', []):
      self.logger.error('unable to reset exits')
      self.oopsie()
    self.timer.singleShot(10000,self.self._enablesignal.emit)
    self.resetConfigPages()

  #########################

  def restoreATCConfig(self):
    configfilename = self.ui.lineEditOptionsRestoreConfig.text()
    if not configfilename:
      return
    if not re.match(r'.*\S',configfilename):
      self.ui.lineEditOptionsRestoreConfig.setText('')
      return
    if not os.path.isFile(configfilename):
      QtGui.QMessageBox.critical(self.MainWindow,self.mytitle, \
       'File, "%s", does not exist or is not a normal file.\n\nTry again.' \
       % (configfilename), QtGui.QMessageBox.Ok)
      self.ui.lineEditOptionsRestoreConfig.setText('')
      return

    while True:
      text, ok = QtGui.QInputDialog.getText(self.MainWindow, \
       self.mytitle + ': load config', \
       'Enter the password for file:\n  "%s"' % configfilename, \
       QtGui.QLineEdit.Password )
      if not ok:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Canceled..', QtGui.QMessageBox.Ok)
        del text
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      if not text:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Canceled.. (no password entered)', QtGui.QMessageBox.Ok)
        del text
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      password = text
      newconfig = anontracon_funcs.read_object_from_embedded_file( \
       configfilename, password)
      if isinstance(newconfig,Exception):
        if QtGui.QMessageBox.critical(self.MainWindow,self.mytitle, \
         'Password invalid or is not a valid config file.\nTry another password?', \
         QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
          return
        else:
          continue
      elif type(newconfig) == dict and not 'type' in newconfig.keys():
        QtGui.QMessageBox.critical(self.MainWindow,self.mytitle, \
         'The embedded object is not a saved config or is corrupted.' + \
         ' Cannot continue..', QtGui.QMessageBox.Ok)
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      elif type(newconfig) == dict and newconfig.type == 'config':
        break
      elif type(newconfig) == dict:
        QtGui.QMessageBox.critical(self.MainWindow,self.mytitle, \
         'The embedded object of type "%s" is not a saved configuration.' + \
         ' Cannot continue..', QtGui.QMessageBox.Ok)
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return

    rety = QtGui.QMessageBox.warning(self.MainWindow,self.mytitle + \
     ': load config', \
     'Do you want to add to your existing configuration or replace it?', \
     'Add','Replace','Cancel')
    if rety == 2:
      return
    elif rety == 1:
      replace = True
    else:
      replace = False

    tmpthread = self.startThread(lambda: setNewConfig(newconfig, replace) )

  #-------------------------------------------------------

  def saveATCConfig(self):
    configfilename = self.ui.lineEditOptionsSaveConfig.text()
    if not configfilename:
      return
    if not re.match(r'.*\S',configfilename):
      self.ui.lineEditOptionsRestoreConfig.setText('')
      return
    if os.path.isFile(configfilename):
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
       'File, "%s", does not exist. Create a new binary file?' % \
       configfilename,  QtGui.QMessageBox.Yes|QtGui.QMessageBox.No) \
       == 16384:
        embed = False
      else:
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
    else:
      embed = True

    while True:
      text, ok = QtGui.QInputDialog.getText(self.MainWindow, \
       self.mytitle + ': save config', \
       'Enter a password for file:\n  "%s"' % configfilename, \
       QtGui.QLineEdit.Password )

      if not ok:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Canceled..', QtGui.QMessageBox.Ok)
        del text
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      if not text or not len(text) >= 12:
        if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Passwords must be 12 or more characters.\n\nTry again?', \
         QtGui.QMessageBox.Yes|QtGui.QMessageBox.No) == 16384:
          del text
          continue
        else:
          self.ui.lineEditOptionsRestoreConfig.setText('')
          return
      password = text

## XXX TODO: FINISH ME! this is just copied from read config
      text, ok = QtGui.QInputDialog.getText(self.MainWindow, \
       self.mytitle + ': save config', \
       'Re-enter the password for file:\n  "%s"' % configfilename, \
       QtGui.QLineEdit.Password )

      if not ok:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Canceled..', QtGui.QMessageBox.Ok)
        del password
        del text
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      if text != password:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Passwords do not match.\n\nTry again.', QtGui.QMessageBox.Ok)
        del text
        continue


      newconfig = anontracon_funcs.read_object_from_embedded_file( \
       configfilename, password)
      if isinstance(newconfig,Exception):
        if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'Password invalid or is not a valid config file.\nTry another password?', \
         QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
          return
        else:
          continue
      elif type(newconfig) == dict and not 'type' in newconfig.keys():
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'The embedded object is not a saved config or is corrupted.' + \
         ' Cannot continue..', QtGui.QMessageBox.Ok)
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return
      elif type(newconfig) == dict and newconfig.type == 'config':
        break
      elif type(newconfig) == dict:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle, \
         'The embedded object of type "%s" is not a saved configuration.' + \
         ' Cannot continue..', QtGui.QMessageBox.Ok)
        self.ui.lineEditOptionsRestoreConfig.setText('')
        return

    rety = QtGui.QMessageBox.warning(self.MainWindow,self.mytitle + \
     ': load config', \
     'Do you want to add to your existing configuration or replace it?', \
     'Add','Replace','Cancel')
    if rety == 2:
      return
    elif rety == 1:
      replace = True
    else:
      replace = False

    tmpthread = self.startThread(lambda: setNewConfig(newconfig, replace) )




  #-------------------------------------------------------

  def setNewConfig(newconfig, replace=True):
    while not self.shuttingdown:
      if self.checkHaveAuth():
        break
      else:
        time.sleep(1)
    if 'hs' in newconfig.keys():
      if replace:
        self.kill_our_hidden_services()
      for i in 'hs':
        if not type(i) == dict:
          self.logger.error('expected dict for hs entry, got %s' \
           % repr(type(dict)) )
          continue
        tmparglist = []
        for j in ['hsport','hstype','hssettings','hsurl','hskey']:
          if j in i.keys():
            tmparglist.append(i[j])
          else:
            tmparglist.append(None)
        if not self.startNewService(*tmparglist):
          self.logger.error('unable to start hidden service: %s' % tmparglist[0] )
          self.debug('startNewService FAIL ! !!: %s' \
           % repr(tmparglist)) #XXX DEBUGGING
    #asdfxyz
    if 'goodexits' in newconfig.keys():
      if replace:
        if not self.cncSend('set_goodexits', [] ):
          self.logger.error('unable to set exit nodes. (za1)')
      if not self.cncSend('add_goodexits', newconfig['goodexits'] ):
        self.logger.error('unable to add exit nodes. (za2)')
    if 'badexits' in newconfig.keys():
      if replace:
        if not self.cncSend('set_badexits', [] ):
          self.logger.error('unable to set bad exit nodes. (zb1)')
      if not self.cncSend('add_goodexits', newconfig['goodexits'] ):
        self.logger.error('unable to add bad exit nodes. (zb2)')
    if 'bridges' in newconfig.keys():
      if replace:
        if not self.cncSend('set_bridges', [] ):
          self.logger.error('unable to set bridges. (zc1)')
      if not self.cncSend('add_bridges', newconfig['bridges'] ):
        self.logger.error('unable to add bridges. (zc2)')

  #########################

  def kill_our_hidden_services(self):
    tmplist = []
    for i in self.running_hidden_services:
      if i[0] in self.our_running_hidden_services.keys():
        tmplist.append(i)
    stopHiddenService(tmplist)

  #asdfxyzz
  #########################

  def monkey(self):
    """For testing, may or may not raise an (uncaught) exception."""
    #for spicing things up with pseudo-random exceptions...
    self.monkeynum += 1
    if self.monkeynum > 4 and self.monkeynum % 2 == 0:
      raise Exception('MONKEY!')

  #######################

  def addBlockNode(self):
    """Get list of nodes to block from ui and send to controller."""
    if not re.search(r'\S',self.ui.plainTextEditConfigBlockNodeSet.toPlainText(),re.MULTILINE):
      return
    self._disablesignal.emit()
    if ( len(self.blockedCountries) + len(self.blockedNodes) ) == 0:
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'Blocking exits may reduce TOR\'s connectivity.\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
    self.debug("block the fingerprint in lineEditConfigBlockNodeSet")
    tmpallblocks = []
    tmpnodes = []
    tmpbadentries = []
    tmpentries = str(self.ui.plainTextEditConfigBlockNodeSet.toPlainText()).split('\n')
    for i in range(len(tmpentries)):
      tmpentry= re.sub(r'\s',r'', tmpentries[i] )
      if re.match(self.re_fingerprint, tmpentry):
        tmpnodes.append( tmpentry )
      elif re.match(self.re_validip, tmpentry):
        tmpnodes.append( tmpentry )
      elif re.match(self.re_validiprange, tmpentry ):
        if re.match(r'.*/4$|.*/8$|.*/12$', tmpentry ):
          tmpiter = re.sub(r'.*/([1248])+$',r'\1', tmpentry)
          try:
            tmpiter = str( int(tmpiter) / 4 )
          except Exception, e:
            self.logger.exception(e)
            tmpbadentries.append(tmpentries[i])
            continue
          else:
            if re.match(self.re_validip, re.sub(r'(.*)/[0-9]+$',r'\1',tmpentry)) and re.match(r'.*(\.0){' + tmpiter + '}/[0-9]+$', tmpentry):
              tmpnodes.append( tmpentry )
            else:
              tmpbadentries.append(tmpentries[i]) 
        else:
          tmpbadentries.append(tmpentries[i])
          continue
      elif re.match(r'.*\S', tmpentries[i]):
        tmpbadentries.append(tmpentries[i])

    if len(tmpbadentries) > 0:
      QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'Only the fingerprints or IP addresses of TOR nodes are allowed. The fingerprint is a 40-character cryptographically-hashed string.\n\nThe following invalid lines were entered:\n' + '\n'.join(tmpbadentries), QtGui.QMessageBox.Ok)
      self._enablesignal.emit()
      return
    elif len(tmpnodes) > 0:
      tmpnodes = list(self.blockedNodes) + tmpnodes
      #and now this, just to add brackets {}....
      tmpcountries = []
      for i in self.blockedCountries:
        tmpcountries.append( re.sub(r'(..)',r'{\1}', i) )
      self.cncSend('add_badexits', tmpcountries + tmpnodes )
    self.resetConfigPages()
    self.timer.singleShot(10000,self._enablesignal.emit)

  ###########################

  def addBlockCountries(self):
    """Get list of countries to block from the ui and send to controller."""
    if len(self.ui.listWidgetConfigBlockCountrySet.selectedItems()) == 0: return
    self._disablesignal.emit()
    if ( len(self.blockedCountries) + len(self.blockedNodes) ) == 0:
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'Blocking exits may reduce TOR\'s connectivity.\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self.resetConfigPages()
        self._enablesignal.emit()
        return
    if len(self.ui.listWidgetConfigBlockCountrySet.selectedItems()) == 0: return
    tmpallblocks = []
    tmpcountries = []
    tmpcountries = ['{' + i + '}' for i in self.blockedCountries ]
    for i in self.ui.listWidgetConfigBlockCountrySet.selectedItems():
      tmpcountries.append('{' + i._my_id + '}')
      i.setSelected(False) 
    self.cncSend('add_badexits', tmpcountries + list(self.blockedNodes) )
    self.resetConfigPages()
    self.timer.singleShot(10000,self._enablesignal.emit)

  ############################

  def clearBlockedExits(self):
    """Clear any setting for bad exits."""
    self._disablesignal.emit()
    self.cncSend('set_badexits', [])
    self.timer.singleShot(10000,self._enablesignal.emit)
    self.resetConfigPages()

  #######################################

  def shutdownATC(self,shutdown_signal=0):
    """DIE!"""
    self.debug('SHUTTING DOWN! signal: %d' % shutdown_signal) #XXX DEBUGGING
    self._disablesignal.emit()
    #I'm using the raw codes returned by the button... I know it's not pretty.
    if shutdown_signal == 0:
      self.debug('shutdown p2') #XXX DEBUGGING
      if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'"Check yosself before you wreck yosself..."\n\nAre you absolutely sure you want ATC to shutdown, causing some settings and services to disappear...?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
        self._enablesignal.emit()
        self.resetOptionsPages()
        return
    #XXX XXX XXX WE NEED TO CLOSE ALL THREADS!!!!!!#**#&$*&$#
    #self.threadLog.exit()
    self.logger.warning('shutdown request received')
    self.debug('s1') #XXX
    #self.logger.warning('closing agent listeners')
#    if hasattr(self.agent,'all_event_listeners'):
#      for i in self.agent.all_event_listeners:
#        try:
#          self.agent.controller.remove_event_listener(i)
#        except Exception, e:
#          self.logger.exception(e)
#    else:
#      self.logger.warning('no event listeners, incomplete agent?')
#    if hasattr(self.agent,'all_status_listeners'):
#      for i in self.agent.all_status_listeners:
#        try:
#          self.agent.controller.remove_status_listener(i)
#        except Exception, e:
#          self.logger.exception(e)
#    else:
#      self.logger.warning('no status listeners, incomplete agent?')
#    try:
#      self.agent._shuterdown(shutdown_signal)
#    except Exception as e:
#      self.logger.exception(e)
    self.debug('s2')
    self.zmq_cnc_socket.close()
    self.debug('s3')
    try:
      self.MainWindow.close()
    except Exception, e:
      self.logger.exception(e)
    self.debug('s4')
    self.logger.warning('closing threads')
    for i in self.threadList:
      i.terminate()
      i.wait()

    self.debug('s5')
    self.debug('closing self......')
    self.setVisible(False)
    self.deleteLater()
    #lockfilename = '/var/lock/atc/atc_main.lock'
    #with open(lockfilename,'w+') as filey:  
      #self.close()
    self.debug('s6')
    self.debug('exiting app (general).......')
    #app.exit(shutdown_signal)
    self.debug('s7')
    #*OR*
    QtGui.qApp.exit(shutdown_signal)
    #*OR*
    self.debug('s8')
    QtGui.qApp.quit()
    #print 'quitting app......'
    #app.exit(1)
    self.debug('s9')
    #app.exit(shutdown_signal)
    self.debug('s10')
    sys.exit(shutdown_signal)
    self.ui.buttonBoxOptionsShutdown.setEnabled(True) #shouldn't actually run..
    

  ######################################

  def clearEverything(self):
    """Clear most ui elements, usually due to TOR stopping or erroring."""
    self.ui.labelLastExit.setText('None\n--\n--\n--')
    self.ui.labelLastExitFlag.setText('*')
    self.ui.labelExitNodesCount.setText('0')
    self.ui.labelBridgeState.setText('Deactivated')
    for i in [ \
     self.ui.listWidgetAllExitNodes,
     self.ui.listWidgetRunningServices,
     self.ui.listWidgetServicesStop,
     self.ui.listWidgetActiveBridges,
     self.ui.listWidgetLimitCountryInfo,
     self.ui.listWidgetLimitNodeInfo,
     self.ui.listWidgetBlockedCountriesInfo,
     self.ui.listWidgetBlockedNodesInfo,
     ]:
      i.clear()
      i.addItem('None...')
      i.setEnabled(False)
    self._enabled = False


  ######################################

  def disableEverything(self):
    """Disable (grey-out) any ui element that can be."""
    for i in [ \
     self.ui.buttonBoxBridgesSet,
     self.ui.buttonBoxClearBridges,
     self.ui.buttonBoxConfigBlockCountrySet,
     self.ui.buttonBoxConfigBlockNodeSet,
     self.ui.buttonBoxConfigBlockReset,
     self.ui.buttonBoxLimitExitSetClear,
     self.ui.buttonBoxLimitExitSetCountry,
     self.ui.buttonBoxLimitExitSetNodes,
     self.ui.buttonBoxOptionsSaveConfig,
     #self.ui.buttonBoxOptionsShutdown,
     self.ui.buttonBoxRestartCircs,
     #self.ui.buttonBoxRestartTor,
     self.ui.buttonBoxOptionsRestoreConfig,
     self.ui.buttonBoxServicesNew,
     self.ui.buttonBoxServicesStart,
     self.ui.buttonBoxServicesStop,
     #self.ui.groupBoxRestartTor,
     self.ui.groupBoxConfigBridges,
     self.ui.groupBoxConfigLimit,
     self.ui.groupBoxConfigBlocked,
     self.ui.groupBoxOptionsSaveRestore,
     self.ui.lineEditOptionsRestoreConfig,
     self.ui.lineEditOptionsSaveConfig,
     self.ui.lineEditServicesStart,
     self.ui.listWidgetActiveBridges,
     self.ui.listWidgetAllExitNodes,
     self.ui.listWidgetBlockedCountriesInfo,
     self.ui.listWidgetBlockedNodesInfo,
     self.ui.listWidgetConfigBlockCountrySet,
     self.ui.listWidgetLimitCountryInfo,
     self.ui.listWidgetLimitExitSetCountry,
     self.ui.listWidgetLimitNodeInfo,
     self.ui.listWidgetRunningServices,
     self.ui.listWidgetServicesNew,
     self.ui.listWidgetServicesStop,
     self.ui.plainTextEditBridges,
     self.ui.plainTextEditConfigBlockNodeSet,
     self.ui.plainTextEditLimitExitSetNodes,
     self.ui.pushButtonBlockedExits,
     self.ui.pushButtonBridgesInfo,
     self.ui.pushButtonCopyActiveBridges,
     self.ui.pushButtonCopyAvailableExits,
     self.ui.pushButtonCopyBlockedCountries,
     self.ui.pushButtonCopyBlockedNodes,
     self.ui.pushButtonCopyExitCountries,
     self.ui.pushButtonCopyExitNodes,
     self.ui.pushButtonCopyRunningServices,
     self.ui.pushButtonExitCountryLimit,
     self.ui.pushButtonExitNodesInfo,
     self.ui.pushButtonObfsInfo,
     self.ui.pushButtonOptionsRestoreConfigBrowse,
     self.ui.pushButtonOptionsSaveConfigBrowse,
     self.ui.pushButtonRunningHiddenServices,
     self.ui.pushButtonServicesStartBrowse,
     #self.ui.commandLinkAboutATC,
     self.ui.commandLinkBlockExit,
     self.ui.commandLinkBridges,
     self.ui.commandLinkButtonConfigAdvanced,
     self.ui.commandLinkButtonUtilities,
     #self.ui.commandLinkButtonViewLog,
     self.ui.commandLinkConfineExitCountries,
     #self.ui.commandLinkCreateNewService,
     #self.ui.commandLinkImportServices,
     #self.ui.commandLinkRestartTor,
     self.ui.commandLinkSaveRestoreConfig,
     #self.ui.commandLinkShutdownATC,
     self.ui.commandLinkStartService,
     self.ui.commandLinkStopService,
     self.ui.commandLinkUseNewExit,
     ]:
      i.setEnabled(False)
    self._enabled = False

  ######################################

  def enableEverything(self):
    """Enable any ui element that could be disabled."""
    for i in [ \
     self.ui.buttonBoxBridgesSet,
     self.ui.buttonBoxClearBridges,
     self.ui.buttonBoxConfigBlockCountrySet,
     self.ui.buttonBoxConfigBlockNodeSet,
     self.ui.buttonBoxConfigBlockReset,
     self.ui.buttonBoxLimitExitSetClear,
     self.ui.buttonBoxLimitExitSetCountry,
     self.ui.buttonBoxLimitExitSetNodes,
     self.ui.buttonBoxOptionsSaveConfig,
     self.ui.buttonBoxOptionsShutdown,
     self.ui.buttonBoxRestartCircs,
     self.ui.buttonBoxRestartTor,
     self.ui.buttonBoxOptionsRestoreConfig,
     self.ui.buttonBoxServicesNew,
     self.ui.buttonBoxServicesStart,
     self.ui.buttonBoxServicesStop,
     self.ui.groupBoxRestartTor,
     self.ui.groupBoxConfigBridges,
     self.ui.groupBoxConfigLimit,
     self.ui.groupBoxConfigBlocked,
     self.ui.groupBoxOptionsSaveRestore,
     self.ui.lineEditOptionsRestoreConfig,
     self.ui.lineEditOptionsSaveConfig,
     self.ui.lineEditServicesStart,
     self.ui.listWidgetActiveBridges,
     self.ui.listWidgetAllExitNodes,
     self.ui.listWidgetBlockedCountriesInfo,
     self.ui.listWidgetBlockedNodesInfo,
     self.ui.listWidgetConfigBlockCountrySet,
     self.ui.listWidgetLimitCountryInfo,
     self.ui.listWidgetLimitExitSetCountry,
     self.ui.listWidgetLimitNodeInfo,
     self.ui.listWidgetRunningServices,
     self.ui.listWidgetServicesNew,
     self.ui.listWidgetServicesStop,
     self.ui.plainTextEditBridges,
     self.ui.plainTextEditConfigBlockNodeSet,
     self.ui.plainTextEditLimitExitSetNodes,
     self.ui.pushButtonBlockedExits,
     self.ui.pushButtonBridgesInfo,
     self.ui.pushButtonCopyActiveBridges,
     self.ui.pushButtonCopyAvailableExits,
     self.ui.pushButtonCopyBlockedCountries,
     self.ui.pushButtonCopyBlockedNodes,
     self.ui.pushButtonCopyExitCountries,
     self.ui.pushButtonCopyExitNodes,
     self.ui.pushButtonCopyRunningServices,
     self.ui.pushButtonExitCountryLimit,
     self.ui.pushButtonExitNodesInfo,
     self.ui.pushButtonObfsInfo,
     self.ui.pushButtonOptionsRestoreConfigBrowse,
     self.ui.pushButtonOptionsSaveConfigBrowse,
     self.ui.pushButtonRunningHiddenServices,
     self.ui.pushButtonServicesStartBrowse,
     self.ui.commandLinkAboutATC,
     self.ui.commandLinkBlockExit,
     self.ui.commandLinkBridges,
     self.ui.commandLinkButtonConfigAdvanced,
     self.ui.commandLinkButtonUtilities,
     self.ui.commandLinkButtonViewLog,
     self.ui.commandLinkConfineExitCountries,
     self.ui.commandLinkCreateNewService,
     self.ui.commandLinkImportServices,
     self.ui.commandLinkRestartTor,
     self.ui.commandLinkSaveRestoreConfig,
     self.ui.commandLinkShutdownATC,
     self.ui.commandLinkStartService,
     self.ui.commandLinkStopService,
     self.ui.commandLinkUseNewExit,
     ]:
      i.setEnabled(True)
    self._enabled = True
 
  ######################################################################## 
  
  def saveATCConfig(self):
    """Save all settings to filename indicated in lineEditOptionsSaveConfig"""
    
    QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'Feature not implemented yet...', QtGui.QMessageBox.Ok)
    self.resetStatusPages()
  
  def restoreATCConfig(self):
    "from filename in lineEditOptionsRestoreConfig"
    QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'Feature not implemented yet...', QtGui.QMessageBox.Ok)
    self.resetStatusPages()
  
  def restartTorQuick(self):
    #agent.controller should be trying to re-authenticate any time it needs to..
    self.logger.warning('restart (quick) request received')
    self.debug(' rtq1 ') #XXX DEBUGGING
    #def tmpfunc(self):
    self._disablesignal.emit()
    self._clearsignal.emit()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
#asdfasdfasdf
    countdown = 20
    self.debug(' rtq2 ') #XXX DEBUGGING
    self.cncSend('set_signal','RELOAD')

    while countdown > 0:
      self.debug(' rtq3 ') #XXX DEBUGGING
      QtGui.QApplication.processEvents()

      if self.checkHaveAuth():
        self.debug(' rtq4 ') #XXX DEBUGGING
        count2 = 20
        while count2 > 0:
          if self.checkHaveAuth():
            self.debug(' rtq5 ') #XXX DEBUGGING
            if not self._enabled:
              QtCore.QTimer.singleShot(5000,self._enablesignal.emit)
            return True
          else:
            self.debug(' rtq6 ') #XXX DEBUGGING
            self.qsleep(1)
        else:
          self.debug(' rtq7 ') #XXX DEBUGGING
          self.logger.warning('unable to re-connect with tor. Hard reset may be required...')
          self._popupsignal.emit('Refresh failed!\nConsult the logs...')
          QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'ERROR:\nQuick reset failed. A hard reset may be required.', QtGui.QMessageBox.Ok)
          return False
      else:
        self.debug(' rtq8 ') #XXX DEBUGGING
        countdown -=1
        self.qsleep(1)
    else:
      self.logger.warning('unable to communicate with tor. Hard reset may be required...')
      self._popupsignal.emit('Refresh failed!\nConsult the logs...')
      QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'ERROR:\nQuick reset failed. A hard reset may be required.', QtGui.QMessageBox.Ok)
      return False

    self.debug(' rtq10 ') #XXX DEBUGGING
    if not self._enabled:
      QtCore.QTimer.singleShot(5000,self._enablesignal.emit)
    tmpthread = self.startThread(tmpfunc)
    self.resetStatusPages()

  ###########################################

  def restartTor(self):
    """Send signal to controller to fully restart TOR."""
    #agent.controller should be trying to re-authenticate any time it needs to..
    self.ui.buttonBoxRestartTor.setEnabled(False)
    self._disablesignal.emit()
    self._clearsignal.emit()
    self.logger.warning('attempting to restart TOR service')
    self.resetStatusPages()
    self.clearEverything()
    self.ui.labelConnStat.setText('Restarting')
    #i should only have to do this once, but it wouldn't work...
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    QtGui.QApplication.processEvents()
    self.debug('r1') #XXX debug
    self.cncSend('set_signal','RESTART')
    #self._disablesignal.emit()
    #procy = subprocess.Popen(['service','tor','restart'],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    #while procy.poll() == None:
    #  time.sleep(0.2)
    #  time.sleep(0)
    #  time.sleep(0)
    #tmpoutput = procy.communicate()
    #self.logger.error('service tor restart: ' + tmpoutput[0])
    #self.logger.error('service tor restart: ' + tmpoutput[1])
    #if not procy.returncode == 0:
    #  self.logger.error('restarting tor failed, returncode ' + \
    #   str(procy.returncode))
    #  self.trayPopup('Failed to restart TOR.\nConsult the logs.')
    # And don't do anything else! agent should handle reconnecting to tor 
    # automatically and send the proper status change...
      
  #XXX #############################

  def startHiddenServiceFile(self):
    """Start embedded hs asdfasdfasdfasdfasdfasdfasdfasdfasdf"""
    #start hs saved/embedded from earlier
    QtGui.QMessageBox.information(self,self.mytitle,'feature not implemented yet', QtGui.QMessageBox.Ok) #XXX
    self.resetServicesPages()

  def stopHiddenService(self,tmpstopitems=None):
    """Finds hidden service indicated by ui and tells controller to stop it.
    Takes an optional list of services to stop or forms the list from the gui.
    e.g. stopHiddenService( [[ '/a/dir','123 127.0.0.1'], ] ) """
    #shut down an hs
    if len(self.ui.listWidgetServicesStop.selectedItems()) == 0:
      return
    for i in [self.ui.buttonBoxServicesStop,self.ui.listWidgetServicesStop]:
      i.setEnabled(False)
    if not tmpstopitems:
      tmpstopitems = [ list(x._my_id) for x in self.ui.listWidgetServicesStop.selectedItems() ]
    tmpkeepitems = [ x for x in self.running_hidden_services if not x in tmpstopitems ]
    if len(tmpkeepitems) > 0:
      self.cncSend('set_hs',[x[:2] for x in tmpkeepitems])
    else:
      self.cncSend('set_hs',[])
    self.resetServicesPages()
    for i in [self.ui.buttonBoxServicesStop,self.ui.listWidgetServicesStop]:
      i.setEnabled(True)

  def startNewHiddenService(self):
    """asdfasdfasdfasdfasdfasdf"""
    #WTF is this??
    for i in self.ui.listWidgetServicesNew.selectedItems():
      if i._my_id == 'basic':
        i.setSelected(False)
        self.ui.stackedWidgetServices.setCurrentWidget(self.ui.pageServicesNewBasic)
      else:
        self.debug('WE CAN\'T DO THAT!!!')
      #TODO: EVERYTHING ELSE!
      #        but that would require a framework, wouldn't it....


  def startBasicHiddenService(self):
    """asdfasdfasdfasdfasdfasdfasdf"""
    self.debug('startBasicHiddenService: START') #XXX DEBUGGING
    tmpport = self.ui.spinBoxServicesNewBasic.value()
    if not tmpport > 0 and not tmpport < 65535:
      return False
    elif '%s 127.0.0.1:%s' % (tmpport,tmpport) \
     in (x[1] for x in self.running_hidden_services):
      #XXX What about virtual port combinations using the same port?!?!?!?!
      QtGui.QMessageBox.warning(self.MainWindow, 'anontracon', 
       'Cannot create the service because one already exists on this port.', 
       QtGui.QMessageBox.Ok)
      return False
    else:
      self.startNewService(str(tmpport),'basic')
    self.resetServicesPages()
    self.debug('startBasicHiddenService: END') #XXX DEBUGGING

  def startNewService(self, hsport=None, hstype=None, hssettings=None,hsurl=None,hskey=None):
    """asdfasdfasdfasdfasdfasdfasdfasdf"""
    # Get a port and a type from the ui. The type is either an internally
    #  understood type (i.e. "basic", etc.) or "script" if it's a script
    #  that was embedded in a file or whatever type correlates to an installed
    #  module.  If it's a script type, then, obviously,
    #  the "hssettings" parameter must be filled in.
    # NOTE: this does not take a foldername as a parameter for the service
    #        as we must trust the agent to make/return that value to us as
    #        it sees fit. (All hail the agent!)
    #TODO: ^^ we'll probably need more arguments than that soon..
    #        and we'll need to check hstypes (once there's more than
    #        just "basic"... 
    self.debug('startNewService: START !!!') #XXX DEBUGGING
    if not type(hsport) == str or not type(hstype) == str:
      self.debug('snsx1') #XXX DEBUGGING
      self.logger.error(' function startNewService requires two strings ' + \
       'as argument but received %s and %s' % \
        ( type(hsport), type(hstype) ) )
      self.oopsie()
      return False
    if not hstype == 'basic':
      self.logger.error(' only "basic" hiddenservice types allowed at this ' + \
       'time. Unexpected type: %s' % ( hstype ) )
      self.oopsie()
      return False
    if re.match(r'^[1-9][0-9]* +127\.0\.0\.1:[1-9][0-9]*$',hsport):
      tmpport = hsport
    elif re.match(r'^[1-9][0-9]*$',hsport):
      tmpport = hsport + ' 127.0.0.1:' + hsport
    else:
      self.logger.error(' tried to start service using bad port information: %s' % \
       port)
      self.oopsie()
      return False
    if tmpport in [ x[1] for x in self.running_hidden_services ]:
      self.logger.error('cannot create hs on port %s, one already exists')
      self.oopsie()
      return False
    tmpdir = self.atctmpdir
    while os.path.exists(tmpdir):
      tmpdir = ''
      for i in range(10):
        tmpdir += random.choice( string.ascii_letters )
      tmpdir = os.path.join(self.atctmpdir,tmpdir)
      if tmpdir in self.our_running_hidden_services.keys():
        self.logger.error(' hidden service detected with missing folder: %s' % \
         ( tmpdir ) )
        tmpdir = self.atctmpdir
    #self.our_running_hidden_services[tmpdir] = { \
    tmphsentry = { \
     'hsport':tmpport,
     'hstype':hstype,
     'hssettings':hssettings,
     'hsurl':None,
     'hskey':None,
     'hsfile':None,
     'hsfilepasswd':None,
     }
    ##  Put the port into the "staging" list until we sort it out
    ##  (prevent race condition with event listener)
    ##TODO: vvv   this may need a thread lock
    self.our_running_hidden_services[1].append(tmpport)
    self.our_running_hidden_services[0].append(tmphsentry)
    tmplist = [(tmpdir,tmpport)] + self.running_hidden_services
    tmprep = self.cncSend('set_hs',[i[:2] for i in tmplist])
    #if len(tmplist) == 0:
    #  self.agent.controller.reset_conf('HiddenServiceOptions')
      #TODO: ^^ this is only needed if bug not fixed in current version of stem
      #      https://trac.torproject.org/projects/tor/ticket/9792
    #XXX  notifyConf will fill in the URL/key for us when it gets detected....
    #
    #
    #
    #for i in range(10):
    #  self.qsleep(1)
    #  try:
    #    tmprep = self.cncSend('get_hsinfo',(None,tmpport))
    #  except Exception, e:
    #    self.logger.exception(e)
    #  else:
    #    if type(tmprep) == list and len(tmprep) == 4:
    #      if tmprep[0] in self.our_running_hidden_services.keys():
    #        self.logger.error('attempting to use hs dir already in use: %s' % \
    #         tmprep[0] )
    #        self.oopsie()
    #        return False
    #      if re.match(self.re_onionaddr,tmprep[2]) and \
    #       re.match(self.re_validrsakey,tmprep[3]):
    #        tmphsentry['hsurl'] = tmprep[2]
    #        tmphsentry['hskey'] = tmprep[3]
    #        self.our_running_hidden_services[tmprep[0]] = tmphsentry
    #        ## take port out of the "staging" list and send a new conf signal
    #        self.our_running_hidden_services[1].remove(tmpport)
    #        try:
    #          tmprep2 = self.cncSend('get_hs')
    #          if not isinstance(tmprep2,Exception):
    #            ## let the listener arrange things with the new hs info
    #            self._confsignal.emit('torconf.hs',tmprep2)
    #          else:
    #            #self.logger.exception(tmprep2)
    #            self.logger.error('could not get new hs list.')
    #            #self.oopsie()
    #        except Exception, e:
    #          self.logger.exception(e)
    #        return True
    #      else:
    #        self.logger.error("failed to retrieve url or key for hs:%s" % \
    #         tmprep[:2] )
    #        self.oopsie()
    if isinstance(tmprep, Exception):
      return False
    elif tmprep:
      return True
    else:
      return False
    # ^^ when we start using more than "basic", we'll probably return the
    #    whole dict..

  ##################################################################

  def startUtility(self):
    """Finds custom utility indicated by ui and starts it."""
    for i in self.ui.listWidgetUtilities.selectedItems():
      tmpname = i._my_id
      if tmpname in self.runningUtilities.keys():
        self.runningUtilities[tmpname].show()
        self.runningUtilities[tmpname].raise_()
      else:
        self.runningUtilities[tmpname]=self.utilities[tmpname].UtilityWidget(self)
        self.runningUtilities[tmpname].show()
        self.runningUtilities[tmpname].raise_()
     

  ####################################################################

  def addTorBridges(self):
    """Takes bridge list from ui, sends to controller."""
    if not re.match(r'.*\S', self.ui.plainTextEditBridges.toPlainText()):
      return
    tmptextlistx = str(self.ui.plainTextEditBridges.toPlainText()).split('\n')
    #clean up input
    tmptextlist = []
    badinputslist = []
    for i in range(len(tmptextlistx)): tmptextlistx[i] = tmptextlistx[i].strip()
    for i in tmptextlistx:
      if not re.match(r'.*\S',i):
        continue
      elif not re.match(self.re_bridgeline_all, i):
        badinputslist.append(i)
        continue
      else:
        tmptextlist.append(i)
        continue
    if len(badinputslist) > 0:
      QtGui.QMessageBox.critical(self.MainWindow,self.mytitle,'ERROR:\nEach line must have a valid IP address and, optionally, a cryptographic fingerprint hash.\n\nAborting: the following lines are not the correct format:\n' + str('\n'.join(badinputslist)), QtGui.QMessageBox.Ok)
      return
    else:
      for i in ( self.ui.plainTextEditBridges, self.ui.buttonBoxBridgesSet, ): i.setEnabled(False)
      if ( len(self.bridges) ) == 0:
        if QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'If you continue, you will only reach TOR through bridges, which means your connectivity may experience issues and your throughput will suffer.\n\nAre you sure you want to continue?', QtGui.QMessageBox.Ok|QtGui.QMessageBox.Cancel) == 4194304:
          self.resetConfigPages()
          for i in ( self.ui.plainTextEditBridges, self.ui.buttonBoxBridgesSet, ): i.setEnabled(True)
          return
      for i in range(len(tmptextlist)):
        tmptextlist[i] = re.sub(r'^ *bridge +',r'',tmptextlist[i])
        tmptextlist[i] = re.sub(r'\s+',r' ',tmptextlist[i])
        tmptextlist[i] = tmptextlist[i].strip()
      tmpremlines = []
      if self.obfs_is_enabled:
        for i in tmptextlist:
          if not re.match(r'^obfs[1-9]? ',i):
            tmpremlines.append(i)
        if len(tmpremlines) > 0:
          QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'WARNING:\nSince you have Obfs-proxying enabled, the following entries will be removed as they are not listed as Obfs-capable:\n' + str('\n'.join(tmpremlines)), QtGui.QMessageBox.Ok)
      else:
        for i in tmptextlist:
          if re.match(r'^obfs[1-9]? ',i):
            tmpremlines.append(i)
            #XXX XXX XXX
            # DON'T FORGET! we need to check obfs proxy...
            #... addd a check here    re_bridgeline_all
        if len(tmpremlines) > 0:
          QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'WARNING:\nSince you do NOT have Obfs-proxying enabled, the following entries will be removed since they are listed as Obfs-capable:\n' + str('\n'.join(tmpremlines)), QtGui.QMessageBox.Ok)
      for i in tmpremlines:
        tmptextlist.remove(i)
      if len(tmptextlist) > 0:
        self.cncSend('add_bridges',tmptextlist + list(self.bridges))
      else:
        QtGui.QMessageBox.warning(self.MainWindow,self.mytitle,'ABORT:\n\nYou did not enter a single valid line. There is nothing to be done...\n\nIf you need more information about bridges, go back and view the info button for bridges.', QtGui.QMessageBox.Ok)
    for i in ( self.ui.plainTextEditBridges, self.ui.buttonBoxBridgesSet, ): i.setEnabled(True)
    self.resetConfigPages()

  ############################################

  def clearBridges(self):
    """...there is no bridge..."""
    self.cncSend('set_bridges',[])
    self.resetConfigPages()
    return

  ###########################################

  def rebuildTorCircuits(self):
    """Send signal to get a new outbound TOR circuit."""
    self.cncSend('set_signal','NEWNYM')
    self.ui.stackedWidgetStatus.setCurrentWidget(self.ui.pageStatusMain)

 
  #####################################################################

  def notifyExit(self,tmpconf):
    """Receive input straight from event: 2-element list, should be 
    a string, "torcirc.exit", and a dict with all the circuits.
    Sends notification to ui."""

    tmpcirc = ['--','*None*','--','--',[]]
    tmpnewicon = None

    if type(tmpconf) != list:
      self.debug("NOTIFY_EXIT:  xsFAIL1 ") #XXX DEBUGGING
      self.logger.error(" notifyExit: bad input type: %s" % type(tmpconf) )
      self.oopsie()
      return False
    elif len(tmpconf) != 2 or type(tmpconf[0]) != str \
     or tmpconf[0] != "torcirc.exit" or type(tmpconf[1]) != dict:
      self.debug("NOTIFY_EXIT:  xsFAIL2 ") #XXX DEBUGGING
      self.logger.error(" notifyExit: malformed list: %s" % repr(tmpconf) )
      self.oopsie()
      return False
    else:
      self.debug("NOTIFY_EXIT:  xss ") #XXX DEBUGGING
      circ_dict = tmpconf[1]
      self.circ_dict = circ_dict

    tmpNodeCount = len( [ x for x in circ_dict.keys() \
     if re.match(r'^[0-9]{1,}$',x) ] )

    self.debug('tmpNodeCount: %s' % repr(tmpNodeCount))

    #if tmpNodeCount > 0 and not self.badConnect:
    #  self._iconsignal.emit('**CONNECTED**')

    if tmpNodeCount > 0:
      self.haveCircs = True
    else:
      self.haveCircs = False


    self.ui.labelExitNodesCount.setText(str(tmpNodeCount))
    self.ui.listWidgetAllExitNodes.clear()

    if not self.badConnect == circ_dict['bad_connect']:
      self.badConnect = circ_dict['bad_connect']

    if tmpNodeCount > 0 and 'last_circ' in circ_dict.keys() and \
     circ_dict['last_circ'] and circ_dict['last_circ'] in circ_dict.keys():
      self.debug("NOTIFY_EXIT:  xs1 ") #XXX DEBUGGING
      #last used circuit still there...
      tmpcirc = circ_dict[circ_dict['last_circ']]
      if circ_dict['bad_connect']:
        tmpnewicon = '**BADCONNECT**'
      else:
        tmpnewicon = '**GOODCONNECT**'
        ## we WERE setting it to the flag here, but that should only
        ## be done by successful STREAM events ('torstatus':'**GOODSTREAM**')
        ## which will refer to the circ_dict for the last exit

    elif 'last_circ' in circ_dict.keys() and \
     'last_circ_backup' in circ_dict.keys() and \
     type(circ_dict['last_circ_backup']) == list and \
     len(circ_dict['last_circ_backup']) >= 4:
      self.debug("NOTIFY_EXIT:  xs2 ") #XXX DEBUGGING
      ### last used circuit is now unavailable...
      if tmpNodeCount > 0:
        ## if we wanted to remove a flag if its exit goes away, we'd
        ##  do that here... but we don't...
        self.debug("NOTIFY_EXIT:  xs2 a ") #XXX DEBUGGING
        tmpnewicon = '**GOODCONNECT**'
      else:
        self.debug("NOTIFY_EXIT:  xs2 c ") #XXX DEBUGGING
        tmpnewicon = '**BADCONNECT**'
      tmpcirc = circ_dict['last_circ_backup']

    elif tmpNodeCount > 0:
      ### we don't have last circuit info but there are circuits..
      self.debug("NOTIFY_EXIT:  xs3 ") #XXX DEBUGGING
      if self.checkHaveAuth():
        self.debug("NOTIFY_EXIT:  xs3 a") #XXX DEBUGGING
        if self.circ_dict['bad_connect']:
          tmpnewicon = '**BADCONNECT**'
        else:
          self.debug("NOTIFY_EXIT:  xs3 a1 ") #XXX DEBUGGING
          tmpnewicon = '**GOODCONNECT**'
          self.ui.labelLastExitFlag.setText('*')
          ### XXX letting the last circ info stay for now....
      else:
        self.debug("NOTIFY_EXIT:  xs3 b ") #XXX DEBUGGING
        self.ui.labelLastExitFlag.setText('*')
        ### let checkHaveAuth change the icon, we wipe the last circ

    elif tmpNodeCount == 0:
      self.debug("NOTIFY_EXIT:  xs4 ") #XXX DEBUGGING
      if self.checkHaveAuth():
        self.debug("NOTIFY_EXIT:  xs4 a ") #XXX DEBUGGING
        tmpnewicon = '**BADCONNECT**'
        self.ui.labelLastExitFlag.setText('*')
        ### XXX letting the last circ info stay for now....
      else:
        self.debug("NOTIFY_EXIT:  xs4 b ") #XXX DEBUGGING
        self.ui.labelLastExitFlag.setText('*')
        ### let checkHaveAuth change the icon, we wipe the last circ

    else:
      self.debug("NOTIFY_EXIT:  xs5 ") #XXX DEBUGGING
      #asdfx
      self.debug("-- CIRC_DICT: %s " % repr(self.circ_dict) )
      tmpnewicon = '**ERROR**'
      #self.ui.labelConnStat.setText('Connected')


    self.debug("NOTIFY_EXIT:  xs6 ") #XXX DEBUGGING

    ## update last circ text in ui
    self.ui.labelLastExit.setText( '\n'.join( [ \
     tmpcirc[1], 
     tmpcirc[2],
     digraphs[tmpcirc[3]] + ' (' + tmpcirc[3] + ')' if tmpcirc[3] \
      in digraphs.keys() else '--',
     re.sub( r'^([A-Z0-9]{4})[A-Z0-9 ]{32,41}([A-Z0-9]{4})$', \
      r'\1....\2',tmpcirc[0]), \
     ]))

    #fill in listWidgetAllExitNodes, starting with most recent
    if circ_dict['last_circ'] in circ_dict.keys() and \
     re.match(r'^[A-Z0-9]{40}$',tmpcirc[0]):
      if 'bandwidth' in tmpcirc[4].keys() and tmpcirc[4]['bandwidth'] > 0:
        tmpbandwidth = str(tmpcirc[4]['bandwidth']) + ' kb/s'
      else:
        tmpbandwidth = '?'
        self.debug('bw fail tmpcirc')
      if 'maxbandwidth' in tmpcirc[4].keys() and \
       tmpcirc[4]['maxbandwidth'] > 0:
          tmpmaxbandwidth = str(tmpcirc[4]['maxbandwidth']) + ' kb/s'
      else:
        tmpmaxbandwidth = '?'
        self.debug('maxbw fail tmpcirc')

      tmpitem = QtGui.QListWidgetItem()
      tmpitem.setText('Nickname: ' + tmpcirc[1] + '\n  IP: ' + tmpcirc[2] \
       + '\n  Country: ' + digraphs[tmpcirc[3]] + ' (' + tmpcirc[3] + \
       ')\n  Signature: ' + tmpcirc[0] + '\n   alleged max bandwidth: ' + \
       tmpbandwidth + ' (circuit max: ' + tmpmaxbandwidth + ')\n' )
      tmpitem.setIcon(QtGui.QIcon(':/flags_small/flag-' + \
       re.sub(r'\?\?',r'00',tmpcirc[3]) + '.png'))
      self.ui.listWidgetAllExitNodes.addItem(tmpitem)
    #and now the other circuits...
    if tmpNodeCount > 0:
      for i in circ_dict.keys():
        if circ_dict[i] != tmpcirc and re.match(r'^[0-9]{1,}$',i):
          if 'bandwidth' in circ_dict[i][4].keys() and \
           circ_dict[i][4]['bandwidth'] > 0:
            tmpbandwidth = str(circ_dict[i][4]['bandwidth']) + ' kb/s'
          else:
            tmpbandwidth = '?'
          if 'maxbandwidth' in circ_dict[i][4].keys() and \
           circ_dict[i][4]['maxbandwidth'] > 0:
            tmpmaxbandwidth = str(circ_dict[i][4]['maxbandwidth']) + ' kb/s'
          else:
            tmpmaxbandwidth = '?'
          tmpitem = QtGui.QListWidgetItem()
          tmpitem.setText('Nickname: ' + circ_dict[i][1] + '\n  IP: ' + \
           circ_dict[i][2] + '\n   Country: ' + digraphs[circ_dict[i][3]] + \
           ' (' + circ_dict[i][3] + ')\n   Signature: ' + circ_dict[i][0] + \
           '\n   alleged max bandwidth: ' + tmpbandwidth + ' (circuit max: ' + \
           tmpmaxbandwidth + ')\n' )
          tmpitem.setIcon(QtGui.QIcon(':/flags_small/flag-' + \
           re.sub(r'\?\?',r'00',circ_dict[i][3]) + '.png'))
          self.ui.listWidgetAllExitNodes.addItem(tmpitem)

    #systray tooltip on mouse hover..
    self.debug("NOTIFY_EXIT: xsf %s" % tmpnewicon) #XXX DEBUGGING
    if tmpnewicon:
      self._iconsignal.emit( tmpnewicon )
    self._tooltipsignal.emit('')
    #self.monkey() #XXX uncomment to test uncaught exceptions


  ########################################################################

  def notifyStatus(self,tmpconf):
    """Takes string as argument, either from TOR: 'Closed', 'Reset', 'Init'...
    or original: 'Error', 'NoExit'...
    Should only be called by listener for TOR status."""
    if not type(tmpconf) == list or not len(tmpconf) == 2 or \
     not type(tmpconf[0]) == str or not tmpconf[0] == 'torstatus' or \
     ( not type(tmpconf[1]) == str and not type(tmpconf[1]) == unicode ):
      self.logger.error(" notifyStatus: malformed input: %s" % repr(tmpconf) )
      self.oopsie()
      return False
    newstatus = tmpconf[1]
    if newstatus == 'Closed':
      self.clearEverything()
      self._disablesignal.emit()
      self._iconsignal.emit('**NOTOR**')
      self.ui.labelConnStat.setText('Not connected')
      self.ui.labelLastExit.setText('None\n--\n--\n--')
      self.ui.listWidgetAllExitNodes.clear()
      self.setToolTip('Not connected to TOR')
      self.trayPopup('Disconnected...')
      self._iconsignal.emit('**NOTOR**')
      self.resetStatusPages()
      self.resetServicesPages()
      self.resetConfigPages()
      self.resetOptionsPages()
    elif newstatus == 'Reset':
      self._disablesignal.emit()
      self._iconsignal.emit('**NOTOR**')
      self.ui.labelConnStat.setText('Restarting')
      self.setToolTip('Restarting TOR')
      self.trayPopup('Restarting...')
      self.checkHaveAuth()
      self.ui.labelLastExit.setText('None\n--\n--\n--')
      self.ui.listWidgetAllExitNodes.clear()
      #tor sometimes gets an occasional sighup which dumps our confs...
      #This keeps our configs in spite of the that...
      #if self.agent.controller.get_conf('__ReloadTorrcOnSIGHUP') == '1':
      #  self.agent.controller.set_conf('__ReloadTorrcOnSIGHUP','0')
      self.ui.labelExitNodesCount.setText('0')
      self.resetStatusPages()
      self.resetServicesPages()
      self.resetConfigPages()
      self.resetOptionsPages()
    elif newstatus == 'Init':
      self._disablesignal.emit()
      self._iconsignal.emit('**BADCONNECT**')
      self.setToolTip('Starting')
      self.trayPopup('Starting...')
      self.ui.labelExitNodesCount.setText('0')

    elif newstatus == 'NoExit':
      if self.checkHaveAuth():
        self._iconsignal.emit('**BADCONNECT**')
      self.ui.listWidgetAllExitNodes.clear()
      self.ui.labelExitNodesCount.setText('0')

    elif newstatus == 'BadConnect':
      self.badConnect = True
      self._iconsignal.emit('**BADCONNECT**')

    elif newstatus == 'GoodConnect':
      self.badConnect = False
      self._iconsignal.emit('**GOODCONNECT**')
    elif newstatus == 'GoodStream':
      self.debug('rcv GOODSTREAM...')
      self.badConnect = False
      self._iconsignal.emit('**GOODSTREAM**')

    elif newstatus == 'Error':
      self._iconsignal.emit('**ERROR**')
      self.setToolTip('An error was encountered...')
      self._disablesignal.emit()
    else:
      self.logger.error('unrecognized status received: ' + str(newstatus))
      self.oopsie()

  ########################################################################

  def notifyConf(self,newconf):
    """Takes 2-element list as argument. List should be of a string and
    a python object referring to a conf identifier and its associated data
    respectively. This function should only be called via listeners to the
    broadcast socket."""
    self.debug('NOTIFY_CONF: ARG: %s' % newconf ) #XXX DEBUGGING
    if type(newconf) != list:
      self.logger.error('received unknown type for conf: expected list, got %s' \
       % str(type(newconf)))
      self.oopsie()
      return False
    elif not len(newconf) == 2:
      self.logger.error('no data received for conf event.')
      self.oopsie()
    #elif not type(newconf[1]) == dict and not type(newconf[1]) == str:
    #  self.logger.error('received unknown type for conf data: expected dict, got %s' str(type(newconf[1])))
    newtype = newconf[0]
    newdata = newconf[1]
    if newtype == 'torconf.other':
      ###dunno, log and move on...
      self.logger.info(' received conf: %s' % repr(newdata) )
      return
    if newtype == 'torconf.hs':
      #NOTE: HiddenServices NOT taken raw from stem event. it is re-parsed
      #      as a tuple(HiddenServiceDir,HiddenServicePort)
      #      e.g. tuple('/my/folder','1234 127.0.0.1:1234')
      for widgey in [ \
       self.ui.listWidgetRunningServices,
       self.ui.listWidgetServicesStop,
       ]:
        widgey.clear()

      tmphslist =  newdata
#      for i in tmphslist:
#        tmphostname = ''
#        try:
#          with open(os.path.join(i[0],'hostname'),'r') as filey:
#            tmphostname = filey.read()
#        except Exception as e:
#          self.logger.exception(e)
#        tmphostname = re.sub(r'\n',r'',tmphostname)
#        if re.match(self.re_onionaddr, tmphostname):
#          #i.append(tmphostname) XXX
#          #ADD TO self.our_running_hidden_services
#          if i[0] in self.our_running_hidden_services.keys():
#            if not self.our_running_hidden_services[i[0]]['hsurl'] == tmphostname:
#              self.our_running_hidden_services[i[0]]['hsurl'] = tmphostname
#            try:
#              with open(os.path.join(i[0],'private_key'),'r') as filey:
#                tmpkey = filey.read()
#            except Exception as e:
#              self.logger.exception(e)
#            else:
#              self.our_running_hidden_services[i[0]]['hskey'] = tmpkey
#          else:
#            self.our_running_hidden_services[i[0]] = { \
#             'hsport':i[1],
#             'hstype':None,
#             'hssettings':None,
#             'hsurl':tmphostname,
#             'hskey':None,
#             }
#
#            try:
#              with open(os.path.join(i[0],'private_key'),'r') as filey:
#                tmpkey = filey.read()
#            except Exception as e:
#              self.logger.exception(e)
#            else:
#              self.our_running_hidden_services[i[0]]['hskey'] = tmpkey
#          #
#        else:
#          self.logger.error('attempting to use unrecognized hostname type: ' \
#           + tmphostname)
#          self.trayPopup('An error occurred.\nConsult the logs.')
#          self.our_running_hidden_services[i[0]] = { \
#           'hsport':i[1],
#           'hstype':None,
#           'hssettings':None,
#           'hsurl':None,
#           'hskey':None,
#           }
#          try:
#            with open(os.path.join(i[0],'hostname'),'r') as filey:
#              tmphostname = filey.read()
#          except Exception as e:
#            self.logger.exception(e)
#          else:
#            self.our_running_hidden_services[i[0]]['hskey'] = tmphostname
#          try:
#            with open(os.path.join(i[0],'private_key'),'r') as filey:
#              tmpkey = filey.read()
#          except Exception as e:
#            self.logger.exception(e)
#          else:
#            self.our_running_hidden_services[i[0]]['hskey'] = tmpkey
#
      self.running_hidden_services = tmphslist
      self.ui.labelRunningServicesCount.setText(str(len(self.running_hidden_services)))
      if len(self.running_hidden_services) == 0:
        ##nothing left to do?
        return True
      else:
        for j in self.running_hidden_services:

          if self.our_running_hidden_services and \
           j[1] in self.our_running_hidden_services[1]:
            #it's in the staging area; now we fill in the blanks...
            self.debug("STAGED HS1") #XXX DEBUGGING
            tmpport = j[1]
            tmpdir = j[0]
            for k in self.our_running_hidden_services[0]:
              if k['hsport'] == tmpport:
                self.our_running_hidden_services[tmpdir] = k
                self.our_running_hidden_services[0].remove(k)
                self.our_running_hidden_services[1].remove(tmpport)
            if not self.our_running_hidden_services[tmpdir]['hsurl'] or \
             not self.our_running_hidden_services[tmpdir]['hskey']:
              tmpinfo = self.cncSend('get_hsinfo',[tmpdir,tmpport])
              if tmpinfo and len(tmpinfo) >= 4:
                self.our_running_hidden_services[tmpdir]['hsurl'] = tmpinfo[2]
                self.our_running_hidden_services[tmpdir]['hskey'] = tmpinfo[3]
              else:
                self.our_running_hidden_services[tmpdir]['hsurl'] = None
                self.our_running_hidden_services[tmpdir]['hsurl'] = None

          if self.our_running_hidden_services and \
           j[0] in self.our_running_hidden_services.keys() and \
           j[1] == self.our_running_hidden_services[j[0]]['hsport']:
            tmphstype = self.our_running_hidden_services[j[0]]['hstype']
            if tmphstype == 'basic':
              tmpport = re.sub(r'^([0-9]*) .*',r'\1',j[1])
              try:
                tmpurl = self.our_running_hidden_services[j[0]]['hsurl']
              except Exception, e:
                self.logger.exception(e)
                self.oopsie()
                tmpurl = None
              if not tmpurl:
                tmpurl = self.get_hsurl(j[0],j[1])
                if not tmpurl: tmpurl = '*unknown*'
              tmptxt = 'Basic\n  We open the port to TOR. You do the rest.\n  URL: %s\n  Port: %s' % ( str(tmpurl), tmpport )
              for widgey in [ \
               self.ui.listWidgetRunningServices,
               self.ui.listWidgetServicesStop,
               ]:
                tmpitem = QtGui.QListWidgetItem()
                tmpitem.setText(tmptxt)
                tmpitem.setIcon(QtGui.QIcon(':/Tango/face-monkey.png'))
                tmpitem._my_id = (j[0],j[1])
                widgey.addItem(tmpitem)
              QtGui.QApplication.processEvents() #XXX
            elif tmphstype == None:
              tmpport = j[1]
              try:
                tmpurl = self.our_running_hidden_services[j[0]]['hsurl']
              except Exception, e:
                self.logger.exception(e)
                self.oopsie()
                tmpurl = None
              if not tmpurl:
                tmpurl = self.get_hsurl(j[0],j[1])
                if not tmpurl: tmpurl = '*unknown*'
              tmptxt = '*unknown service*\n  URL: %s\n  Port: %s\n  Path: %s' % \
               ( tmpurl, tmpport, j[0] )
              for widgey in [ \
               self.ui.listWidgetRunningServices,
               self.ui.listWidgetServicesStop,
               ]:
                tmpitem = QtGui.QListWidgetItem()
                tmpitem.setText(tmptxt)
                tmpitem.setIcon(QtGui.QIcon(':/atc_logos/atc_icon_unknown.png'))
                tmpitem._my_id = (j[0],j[1])
                widgey.addItem(tmpitem)
              QtGui.QApplication.processEvents() #XXX
              #XXX ^^ will this cause a hang if a signal-spawned process
              #        is stuck elsewhere...?
              del tmpitem
              del tmptxt
              #XXX ^^ does this cause item to fail if we garbage collect
              #       before qt processes it?  **UPDATE: yes!
            else:
              #XXX OOPS! We only know how to do "basic" right now...
              self.logger.error('processed hidden service of unknown type: %s' % \
               ( tmphstype ) )
              self.oopsie()
          elif j[0] in self.our_running_hidden_services.keys() and \
           not j[1] == self.our_running_hidden_services[j[0]]['hsport']:
            #this shouldn't be needed. EVERYTHING should already be processed
            # into our_running_hidden_services...
            if j[0] in self.our_running_hidden_services.keys():
              tmpcrap = ( [j[0]], \
               self.our_running_hidden_services[j[0]]['hsport'] )
            else:
              tmpcrap = (None,None)
            self.logger.error('current service ' + \
             '(%s,%s) mismatch for recorded service %s' % \
             ( j[0], j[1], tmpcrap ) )
            self.oopsie()
            tmpport = j[1]

            try:
              tmpurl = self.our_running_hidden_services[j[0]]['hsurl']
            except Exception, e:
              self.logger.exception(e)
              self.oopsie()
              tmpurl = None
            if not tmpurl:
                tmpurl = self.get_hsurl(j[0],j[1])
                if not tmpurl: tmpurl = '*unknown*'
            tmptxt = '*unknown service*\n  URL: %s\n Port: %s\n Path: %s' % \
             ( str(tmpurl), tmpport, j[0] )
            for widgey in [ \
             self.ui.listWidgetRunningServices,
             self.ui.listWidgetServicesStop,
             ]:
              tmpitem = QtGui.QListWidgetItem()
              tmpitem.setText(tmptxt)
              tmpitem.setIcon(QtGui.QIcon(':/atc_logos/atc_icon_unknown.png'))
              tmpitem._my_id = (j[0],j[1])
              widgey.addItem(tmpitem)
            QtGui.QApplication.processEvents() #XXX
            del tmpitem
            del tmptxt
            #XXX ^^ does this cause item to fail if we garbage collect
            #       before qt processes it?

          elif self.unknown_hidden_services and \
           j[0] in self.unknown_hidden_services.keys() and \
           j[1] == self.unknown_hidden_services[j[0]]['hsport']:
            tmpport = self.unknown_hidden_services[j[0]]['hsport']
            tmpurl = self.unknown_hidden_services[j[0]]['hsurl']
            if not tmpurl:
              tmpurl = '*unknown*'
            tmptxt = '*unknown service*\n  URL: %s\n Port: %s\n Path %s' % \
             ( str(tmpurl), tmpport, j[0] )
            for widgey in [ \
             self.ui.listWidgetRunningServices,
             self.ui.listWidgetServicesStop,
             ]:
              tmpitem = QtGui.QListWidgetItem()
              tmpitem.setText(tmptxt)
              tmpitem.setIcon(QtGui.QIcon(':/atc_logos/atc_icon_unknown.png'))
              tmpitem._my_id = (j[0],j[1])
              widgey.addItem(tmpitem)
            QtGui.QApplication.processEvents() #XXX

          else:
            ### it's not one of OUR running services...
            ### add to our dict of unknown services... hsport hsurl
            #
            ## first, purge any similar entries...
            for k in [ self.our_running_hidden_services, \
             self.unknown_hidden_services ]:
              if j[0] in k.keys():
                k.pop(j[0])
            tmpport = j[1]
            tmpurl = self.get_hsurl(j[0],j[1])
            if not tmpurl: tmpurl = None
            self.unknown_hidden_services[j[0]] = \
             {'hsport':tmpport,'hsurl':tmpurl}
            #
            if not tmpurl:
              tmpurl = '*unknown*'
            tmptxt = '*unknown service*\n  URL: %s\n Port: %s\n Path %s' % \
             ( str(tmpurl), tmpport, j[0] )
            for widgey in [ \
             self.ui.listWidgetRunningServices,
             self.ui.listWidgetServicesStop,
             ]:
              tmpitem = QtGui.QListWidgetItem()
              tmpitem.setText(tmptxt)
              tmpitem.setIcon(QtGui.QIcon(':/atc_logos/atc_icon_unknown.png'))
              tmpitem._my_id = (j[0],j[1])
              widgey.addItem(tmpitem)
            QtGui.QApplication.processEvents() #XXX
            #XXX ^^ will this cause a hang if a signal-spawned process
            #        is stuck elsewhere...?
            del tmpitem
            del tmptxt
          for dicty in [ self.our_running_hidden_services, \
           ]:
            for akey in dicty.keys():
              if not type(akey) == str:
                pass
              elif not [ akey, dicty[akey]['hsport'] ] \
               in self.running_hidden_services:
                self.debug("RUNSERV: POP: %s: %s" \
                 % ( akey, repr(dicty[akey]) ) ) #XXX DEBUGGING
                dicty.pop(akey)

          for dicty in [ \
            self.unknown_hidden_services, ]:
            for akey in dicty.keys():
              if not [ akey, dicty[akey]['hsport'] ] \
               in self.running_hidden_services:
                self.debug("RUNSERV: POP: %s: %s" \
                 % ( akey, repr(dicty[akey]) ) ) #XXX DEBUGGING
                dicty.pop(akey)

 
#    elif newtype == 'UseBridges':
#      if len(newconf['UseBridges']) > 1:
#        self.logger.error('strange config received for "UseBridges": ' + \
#         str(newconf['UseBridges']) )
#      if '1' in newconf['UseBridges']:
#        self.ui.labelBridgeState.setText('Activated')
#        self.ui.labelBridgesCount.setText(str(len(self.bridges)))
#        self.ui.listWidgetActiveBridges.clear()
#        for i in self.bridges:
#          self.ui.listWidgetActiveBridges.addItem(i)
#        self.ui.labelBridgesCount.setText(str(len(self.bridges)))
#      elif '0' in newconf['UseBridges']:
#        self.ui.labelBridgeState.setText('Deactivated')
#        self.ui.listWidgetActiveBridges.clear()
#        self.ui.listWidgetActiveBridges.addItem('None...')
#        self.ui.labelBridgesCount.setText('0')

    elif newtype == 'torconf.bridges':
      self.ui.listWidgetActiveBridges.clear()
      tmpbridgelist = newdata
      if tmpbridgelist == None: tmpbridgelist = []
      if len(tmpbridgelist) == 0:
        self.bridges = set()
        self.ui.labelBridgeState.setText('Inactive')
        self.ui.labelBridgesCount.setText('0')
      else:
        self.ui.labelBridgeState.setText('Activated')
        self.bridges = set(tmpbridgelist)
        for i in self.bridges:
          #asdfasdfasdf
          self.ui.listWidgetActiveBridges.addItem(i)
        self.ui.labelBridgesCount.setText(str(len(self.bridges)))
        self.bridges = set(tmpbridgelist)
        del tmpbridgelist

    elif newtype == 'torconf.goodexits':
      self.limitCountries = set()
      self.limitNodes = set()
      self.limitOther = set()
      self.ui.listWidgetLimitCountryInfo.clear()
      self.ui.listWidgetLimitNodeInfo.clear()
      for j in newdata:
        if j == '':
          continue
        elif re.match(r'^{..}$',j):
          self.limitCountries.add(j.strip('{}'))
        elif re.match(self.re_fingerprint,j) or re.match(self.re_validip,j) \
         or re.match(self.re_validiprange,j):
          self.limitNodes.add(j)
        elif j:
          self.limitOther.add(j)
          self.logger.error('unidentified exit node inclusion ' + \
           'requested in conf: %s' % ( j ) )
          self.oopsie()
      #we have to re-create these widgets every time because they cannot
      # be shared ever... I know, I hate it, too....
      for j in self.fill_country_widgets_list():
        if j._my_id in self.limitCountries:
          self.ui.listWidgetLimitCountryInfo.addItem(j)
      for j in self.limitNodes:
        if re.match(self.re_validip,j):
          self.ui.listWidgetLimitNodeInfo.addItem('IP Address: ' + j)
        elif re.match(self.re_validiprange,j):
          self.ui.listWidgetLimitNodeInfo.addItem('IP Address Range: ' + j)
        elif re.match(self.re_fingerprint,j):
          self.ui.listWidgetLimitNodeInfo.addItem('Fingerprint: ' + j)
        else:
          #probably a nickname or whatnot, meaning we didn't make it...
          self.ui.listWidgetLimitNodeInfo.addItem('Other: ' + j)
      self.ui.labelLimitCount.setText(str( len(self.limitNodes) + len(self.limitCountries) + len(self.limitOther) ))

    elif newtype == 'torconf.badexits':
      self.blockedCountries = set()
      self.blockedNodes = set()
      self.blockedOther = set()
      self.ui.listWidgetBlockedCountriesInfo.clear()
      self.ui.listWidgetBlockedNodesInfo.clear()
      for j in newdata:
        if j == '':
          continue
        elif re.match(r'^{..}$',j):
          self.blockedCountries.add(j.strip('{}'))
        elif re.match(self.re_fingerprint,j) or re.match(self.re_validip,j) \
         or re.match(self.re_validiprange,j):
          self.blockedNodes.add(j)
        elif j:
          self.blockedOther.add(j)
          self.logger.error('unidentified exit node exclusion requested ' + \
           'in conf: %s' % ( j ) )
          self.oopsie()
      for j in self.fill_country_widgets_list():
        if j._my_id in self.blockedCountries:
          self.ui.listWidgetBlockedCountriesInfo.addItem(j)
      for j in self.blockedNodes:
        if re.match(self.re_validip,j):
          self.ui.listWidgetBlockedNodesInfo.addItem('IP Address: ' + j)
        elif re.match(self.re_validiprange,j):
          self.ui.listWidgetBlockedNodesInfo.addItem('IP Address Range: ' + j)
        elif re.match(self.re_fingerprint,j):
          self.ui.listWidgetBlockedNodesInfo.addItem('Fingerprint: ' + j)
        else:
          #probably a nickname, meaning we didn't make it...
          self.ui.listWidgetBlockedNodesInfo.addItem('Other: ' + j)
      self.ui.labelBlockedCount.setText(str( len(self.blockedNodes) + len(self.blockedCountries) + len(self.blockedOther) ))
    self.debug("NOTIFY_CONF: ...z5") #XXX DEBUGGING

  ##########################################################################

  def get_hsurl(self,tmpdir,tmpport=None):
    """Takes string as argument. String foldername of hidden service will be
    checked and return hidden service url as string (or bool False if error
    occurs."""
    self.debug("GET_HSURL: START: %s" % tmpdir ) #XXX DEBUGGING
    if type(tmpdir) == unicode:
      tmpdir = str(tmpdir)
    if not type(tmpdir) == str:
      self.logger.error(" get_hsurl: expected string, got %s" % type(tmpdir) )
      self.oopsie()
      return False
    try:
      tmpinfo = self.cncSend('get_hsinfo',[tmpdir,tmpport])
    except Exception, e:
      self.logger.exception(e)
      self.oopsie()
      return False
    else:
      tmpurl = tmpinfo[2]
      if re.match(self.re_onionaddr,tmpurl):
        return tmpurl
      else:
        self.logger.error(" get_hsurl: invalid hostname returned from %s" % \
          ( tmpdir ) )
        self.oopsie()
        return False

  ############################################################

  def set_tooltip(self,tmpstr):
    #systray tooltip on mouse hover..
    tmptooltip = ''
    if re.search(r'\S',tmpstr):
      tmptooltip = tmpstr
    else:
      try:
        tmpcirc = self.circ_dict[circ_dict['last_circ']]
      except Exception:
        try:
          tmpcirc = self.circ_dict['last_circ_backup']
        except Exception:
          tmpcirc = ['--','--','--','--']
      if len(tmpcirc) < 4:
        tmpcirc = ['--','--','--','--']
      tmptooltip = '\n'.join([ \
       str( self.ui.labelConnStat.text() ),
       'Last exit:', 
       tmpcirc[2] ,
       digraphs[tmpcirc[3]][:12] + ' (' + tmpcirc[3] + ')' if tmpcirc[3] \
        in digraphs.keys() else '--',
       #re.sub(r'^(.{5}).*(.{5})$',r'\1...\2', tmpcirc[0]),
       #'(available: ' + str(tmpNodeCount) + ')',
       ])

    self.setToolTip(tmptooltip)


  ##################################################################

  def checkHaveAuth(self):
    """Returns True if connected to stem and stem is authenticated to Tor.
    Returns False otherwise. Also, changes tray icon accordingly."""
    tmprep = self.cncSend('is_authenticated')
    self.debug("# checkHaveAuth: %s " % repr(tmprep) ) #XXX DEBUGGING
    if isinstance(tmprep, Exception):
      self._iconsignal.emit('**ERROR**')
      return False
    elif tmprep == True:
      if not self.haveAuth:
        self.haveAuth = True
        self._iconsignal.emit('**GOODCONNECT**')
      if not self._enabled:
        self._enablesignal.emit()
    elif tmprep == False:
      if self.haveAuth:
        self.haveAuth = False
        self._iconsignal.emit('**NOTOR**')
      if self._enabled:
        self._enablesignal.emit()
    else:
      self.logger.error("unidentified auth return data: %s" % ( tmprep ) )
      self.oopsie()
      #self._iconsignal.emit('**ERROR**')
      tmprep = False
    return tmprep

  ###########################################################################


  def appendATCLog(self,tmpstr):
    newsize = self.max_log_length / 2
    tmpstrlen = len(tmpstr)

    if tmpstrlen > self.max_log_length:
      tmpoffset = ( tmpstrlen - self.max_log_length ) + newsize
      #cut to half the max length and then next newline...
      tmpstr = re.sub( r'^[^\n]*\n', r'', tmpstr[tmpoffset:] )
      tmpstr += ( '\n**Log truncated: entry too large (%d)***\n' % tmpstrlen)

    self.ui.textBrowserATCLog.append(tmpstr)
    tmptotallen = len(self.ui.textBrowserATCLog.toPlainText())
    if tmptotallen > self.max_log_length: 
      #cut to half the max length and then next newline...
      tmpoffset = ( tmptotallen - self.max_log_length ) + newsize
      self.ui.textBrowserATCLog.setText( re.sub( r'^[^\n]*\n', r'', \
       str(self.ui.textBrowserATCLog.toPlainText()[tmpoffset:]) ) )
      self.ui.textBrowserATCLog.append( \
       '\n**Log truncated: too large (%d)**\n' % tmptotallen)

  def appendTORLog(self,tmpstr):
    newsize = self.max_log_length / 2
    tmpstrlen = len(tmpstr)

    if tmpstrlen > self.max_log_length:
      tmpoffset = ( tmpstrlen - self.max_log_length ) + newsize
      #cut to half the max length and then next newline...
      tmpstr = re.sub( r'^[^\n]*\n', r'', tmpstr[tmpoffset:] )
      tmpstr += ( '\n**Log truncated: entry too large (%d)***\n' % tmpstrlen)

    self.ui.textBrowserTORLog.append(tmpstr)
    tmptotallen = len(self.ui.textBrowserTORLog.toPlainText())
    if tmptotallen > self.max_log_length: 
      #cut to half the max length and then next newline...
      tmpoffset = ( tmptotallen - self.max_log_length ) + newsize
      self.ui.textBrowserTORLog.setText( re.sub( r'^[^\n]*\n', r'', \
       str(self.ui.textBrowserTORLog.toPlainText()[tmpoffset:]) ) )
      self.ui.textBrowserTORLog.append( \
       '\n**Log truncated: too large (%d)**\n' % tmptotallen)

  def buildFAQ(self):
    if os.path.isfile(os.path.join(atc_folder,'FAQ.txt')):
      faqfilename = os.path.join(atc_folder,'FAQ.txt')
    elif os.path.isfile('FAQ.txt'):
      faqfilename = 'FAQ.txt'
    with open(faqfilename, 'r') as filey:
      mylines = filey.readlines()
    for i in range(len( mylines)):
      mylines[i] = re.sub(r'<',r'.',mylines[i])
      mylines[i] = re.sub(r'^(Q:.*)',r'<b><i>\1</b></i>',mylines[i])
      mylines[i] = re.sub(r'$',r'<br>',mylines[i])
    text_browser = QtGui.QTextBrowser()
    text_browser.setWindowTitle('ATC: FAQ')
    text_browser.setText(''.join(mylines))
    self.atc_faq = text_browser

  def showHelpFAQ(self):
    self.atc_faq.show()
    self.atc_faq.raise_()

  def showMainWindow(self):
    if self.MainWindow.hasFocus():
      self.MainWindow.hide()
    else:
      self.MainWindow.show()
      self.MainWindow.raise_()
 
  def makeTrayMenus(self):
    self.click_menu = QtGui.QMenu("Openz")
    menuxShowMain = QtGui.QAction(QtGui.QIcon('exit.png'), 'Show &ATC..', self)
    menuxShowMain.triggered.connect(self.showMainWindow) #asdfasdf
    menuxShowQuickInfo = QtGui.QAction(QtGui.QIcon('exit.png'), 'Quick &Info..', self)
    self.click_menu.addAction(menuxShowMain)
    self.click_menu.addAction(menuxShowQuickInfo)
    self.setContextMenu(self.click_menu)
    #self.connect(self, QtCore.SIGNAL('triggered()'), self.click_menu)
    #tmpicon = QtGui.QIcon.fromTheme("document-open")
    #self.addAction(QtGui.QAction(tmpicon, "Hidden Services...", self))

  def oopsie(self):
    """Takes no arguments. Tell the ui something bad happened."""
    try:
      self._iconsignal.emit('**ERROR**')
      self._popupsignal.emit('Error encountered!\n (Consult the logs.)')
    except Exception, e:
      self.debug("OOPSIE FAIL: %s" % repr(e)) #XXX DEBUGGING
      raise e

  def change_icon(self, icon):
    """Takes a string for argument. Changes the icon in the system 
    tray. This should only be called via the Qt signal "_iconsignal". 
    Accepted strings are '**GOODCONNECT**', '**GOODSTREAM**', '**BADCONNECT**',
    '**NOTOR**', '**ERROR**' or a country digraph (lowercase, 
    ex: 'de' for Germany)"""

    ### get one of numerous strings and make that one of only 5 or 6 strings:
    ###    '**GOODCONNECT**':  able to exit but haven't done so yet
    ###    '**BADCONNECT**':   talking to tor but it cannot exit for some reason
    ###    '**NOTOR**': cannot talk to tor
    ###    '**ERROR**':        something went wrong
    ###    '**GOODSTREAM**':   find last exit in circ_dict, use its flag
    ###    country digraph:    the flag to show (i.e. 'de' for Germany)
    ### ...and then change the icon accordingly...

    ### TODO: why take so many different incoming strings? remove unnecessaries!

    self.debug("*** CHANGE_ICON: %s %s %s %s" % \
     ( icon, self.circ_dict['bad_connect'], self.badConnect, self.haveCircs ) )
    tmpNodeCount = len( [ x for x in self.circ_dict.keys() \
     if re.match(r'[0-9]{1,}$',x) ] )
    self.debug(repr(tmpNodeCount))
    try:
      icon = unicode(icon)
    except Exception, e:
      self.debug('TOUTF8 FAIL !! 1 ') #XXX DEBUGGING
    lastIcon = icon
    if icon == '**ERROR**':
      #something somewhere messed up....
      lastIcon = '**ERROR**'
      self.ui.labelConnStat.setText('Unknown (error)')
      self.ui.labelLastExitFlag.setText('*')
      self._disablesignal.emit()
      self._tooltipsignal.emit('There was an error!\nConsult the logs.')
    elif icon == '**NOTOR**':
      self.debug('XL1 !') #XXX DEBUGGING
      #cannot connect to TOR at all, maybe it isn't running...
      lastIcon = '**NOTOR**'
      self.ui.labelConnStat.setText('Unavailable (disconnected)')
      self.ui.labelLastExitFlag.setText('*')
      self._disablesignal.emit()
      self._tooltipsignal.emit('Unable to access TOR...')
      self._tooltipsignal.emit('Unable to access TOR...')
    elif icon == '**BADCONNECT**':
      self.debug('XN1 !') #XXX DEBUGGING
      self._enablesignal.emit()
      self._tooltipsignal.emit('')

    elif icon == '**GOODCONNECT**':
      self.debug('XL4   %s' % tmpNodeCount) #XXX DEBUGGING
      try:
        self.debug(type(tmpNodeCount))
      except Exception,e:
        self.debug(repr(e))
        self.debug('tmpNodeCount wtf')
      if tmpNodeCount > 0:
        self.debug(" XL4 lasticon: %s" % self.lastIcon)
        if re.match(r'[a-z0?][a-z0?]$',self.lastIcon):
          ## connection is good, leave the flag that's already there
          lastIcon = ''
      else:
        ## good connection, but no exits...
        lastIcon = '**BADCONNECT**'

    elif icon == '**GOODSTREAM**':
      self.debug('XO1 !') #XXX DEBUGGING
      ### same as **GOODCONNECT** but don't mess with circ info...
      if tmpNodeCount > 0:
        self.debug('XO1 !') #XXX DEBUGGING
        if self.circ_dict['last_circ'] in self.circ_dict.keys() and \
         len(self.circ_dict[self.circ_dict['last_circ']]) >= 4:
          lastIcon = self.circ_dict[self.circ_dict['last_circ']][3]
        elif not re.match(r'[a-z0?][a-z0?]$',self.lastIcon):
          self.debug('X01 no last circ !!') #XXX DEBUGGING
          lastIcon = '**GOODCONNECT**'
        else:
          self.debug('X01 wtf  1 !!') #XXX DEBUGGING
          lastIcon = '**BADCONNECT**'
      else:
        self.debug('XO2 !') #XXX DEBUGGING
        lastIcon = '**BADCONNECT**'
      self._enablesignal.emit()
      self._tooltipsignal.emit('')
    elif tmpNodeCount == 0:
      self.debug('XO3 !') #XXX DEBUGGING
      lastIcon = '**BADCONNECT**'
      self._enablesignal.emit()
      self._tooltipsignal.emit('')
    else:
      if icon in digraphs.keys():
        #FUCK! we are ASSUMING it's in there!
        #TODO: find a way to CHECK the resource data
        #
        ## So we got a flag (from notifyExit), now check to see it's legit
        if self.badConnect:
          lastIcon = self.disconnected_icon
          self.ui.labelConnStat.setText('Running (disconnected)')
          self.ui.labelLastExitFlag.setText('*')
        else:
          ### an unfortunate side-effect when the connection goes down
          ###  is that the circuits linger for a while, staying "BUILT"
          ###  even after they fail. This ensures our failed state doesn't
          ###  get overridden by these undead circuits until we get a healthy
          ###  report back (i.e. GoodConnect)...
          self.ui.labelConnStat.setText('Connected')
          iconfile = ":/flags_small/flag-" + re.sub(r'\?\?',r'00',icon) + ".png"
          lastIcon = QtGui.QIcon(iconfile)
          self.ui.labelLastExitFlag.setPixmap( \
           QtGui.QPixmap(':/flags_small/flag-' + re.sub(r'\?\?',r'00',icon) + '.png') )
        self._enablesignal.emit()
      else:
        iconfile = ":/flags_small/flag-00.png"
        self.ui.labelLastExitFlag.setText('*')

    ## SET THE ICON

    ## ...but not with something empty...
    if lastIcon:
      self.lastIcon = lastIcon
    self.debug('icon: %s' % lastIcon) #XXX DEBUGGING
    if re.match( r'[a-z0?][a-z0?]$', lastIcon ):
      iconfile = ":/flags_small/flag-%s.png" % re.sub(r'\?\?',r'00',lastIcon)
      self.setIcon( QtGui.QIcon(iconfile))
      self.ui.labelLastExitFlag.setPixmap( QtGui.QPixmap( iconfile) )
      if not self._enabled:
        self._enablesignal.emit()
    else:
      if lastIcon == '**NOTOR**':
        self.ui.labelLastExitFlag.setText('*')
        self.setIcon(self.notor_icon)
        if self._enabled:
          self._disablesignal.emit()
      elif lastIcon == '**BADCONNECT**':
        self.setIcon( self.disconnected_icon)
        self.ui.labelConnStat.setText('Running (disconnected)')
        self.ui.labelLastExitFlag.setText('*')

      elif lastIcon == '**GOODCONNECT**':
        self.ui.labelConnStat.setText('Connected')
        self.setIcon( self.connected_icon)
        if not self._enabled:
          self._enablesignal.emit()

      elif lastIcon == '**ERROR**':
        self.setIcon( self.error_icon)
        self.ui.labelConnStat.setText('Unknown (error)')
        self.ui.labelLastExitFlag.setText('*')

      else:
        self.debug('WTF unknown icon !!! !!! %s' % repr(lastIcon))


        


  #--------------------------------------------------

  #XXX This ain't working... no left-clicky menu...
  def click_trap(self, value):
    if value == self.Trigger: #left click!
      self.click_menu.exec_(QtGui.QCursor.pos())

  def trayPopup(self, message):
    """Takes string as argument and shows it in popup bubble next
    to tray icon."""
    QtCore.QTimer.singleShot(100,lambda:self.showMessage(self.mytitle,message))
    
def testmain():
  """For testing in interactive interpreters: instead of running "main" and
  blocking, this returns a 2-element tuple containing a QtApplication and
  a SystemTrayIcon."""
  #for testing in interactive shell. remember to catch that returned tuple!!
  sys.excepthook = exceptyclosure(logfilename='/tmp/atc_main.log')
  logger = _create_log()
  app = QtGui.QApplication([])
  #if not checklockfile():
  #  logger.critical('failed to create lockfile. abort.\n')
  #  sys.exit(1)
  tray = SystemTrayIcon(logger=logger)
  sys.excepthook = exceptyclosure(logfilename='/tmp/atc_main.log',logger=logger,alertfunction=lambda:tray.trayPopup('Error! Uncaught exception!\nConsult the logs...') )
  tray.show()
  #set the exec loop going
  #sys.exit(app.exec_())
  #QtCore.SIGNAL("triggered()"), QtGui.qApp, QtCore.SLOT("quit()"))
  return (app,tray)


def main():
  sys.excepthook = exceptyclosure(logfilename='/tmp/atc_main.log')
  logger = _create_log()
  app = QtGui.QApplication([])
  #if not checklockfile():
  #  logger.critical('failed to create lockfile. abort.')
  #  sys.exit(1)
  tray = SystemTrayIcon(logger=logger)
  sys.excepthook = exceptyclosure(logfilename='/tmp/atc_main.log',logger=logger,alertfunction=lambda:tray.trayPopup('Error! Uncaught exception!\nConsult the logs...') )
  sys.stderr.write('AAAAAAAAAAAAAAA') #XXX DEBUGGING
  #set the exec loop going
  sys.exit(app.exec_())
  sys.stderr.write('BBBBBBBBBBBBBBB') #XXX DEBUGGING
  #QtCore.SIGNAL("triggered()"), QtGui.qApp, QtCore.SLOT("quit()"))

if __name__ == '__main__':
  main()
