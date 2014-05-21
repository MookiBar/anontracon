# -*- coding: utf-8 -*-

#Ui element designed with QtDesigner, converted with pyuic4
#
#NOTE: this (and all atc utilities) is designed to accept the atc systemtray
#      instance AS IS. This means that it must search for the controller
#      (tray.agent.controller) and main window (tray.MainWindow) from 
#      within that class hierarcy. This is designed to run in ATC....

from PyQt4 import QtCore, QtGui
from digraphs import digraphs
import stem

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

name = 'name of this module' #XXX EDIT! keep it super short...
description = 'A description of what this does' #XXX EDIT!

class Ui_Widget(object):
    #XXX This should be copied from the file created by qt-designer
    #    After making a ".ui" file in qt-designer, run "pyuic4" on it
    #    to produce the python content you need...
    def setupUi(self, DialogIpLookup):
        pass #XXX
    def retranslateUi(self, DialogIpLookup):
        pass #XXX

class UtilityWidget(QtGui.QWidget):
    def __init__(self,parent):
        #This is what gets instantiated by ATC...
        #XXX change from "QtGui.QWidget" to anything that inherits from QWidget
        #      The stuff below is mostly type-checking. you can make your own..
        #      Just remember, the stem controller (for tor) is at
        #      parent.agent.controller
        if parent == None:
            raise TypeError('parent must be set to a QWidget inherited object')
            return False
        if not type(parent.agent.controller) == stem.control.Controller:
            raise TypeError('parent.agent.controller must be set to a stem.control.Controller instance')
            return False
        #and now we get the widget working...
        super(QtGui.QWidget, self).__init__(parent.MainWindow)
        self.ui = Ui_Widget() #XXX change to what's pasted above
        self.ui.setupUi(self)
        self.show()
    def resetstuff(self):
        pass #XXX add your own functions....
    def closeEvent(self,event):
        #XXX your widget should probably be cleaned up when closed...
        self.resetstuff()
        event.accept()

