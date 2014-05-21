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
import re

try:
    _fromUtf8 = QtCore.QString.fromUtf8
except AttributeError:
    _fromUtf8 = lambda s: s

name = 'Ip Lookup'
description = 'Get Country of IP address from geo-database'

class Ui_DialogIpLookup(object):
    def setupUi(self, DialogIpLookup):
        DialogIpLookup.setObjectName(_fromUtf8("DialogIpLookup"))
        DialogIpLookup.resize(214, 82)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(DialogIpLookup.sizePolicy().hasHeightForWidth())
        DialogIpLookup.setSizePolicy(sizePolicy)
        DialogIpLookup.setMaximumSize(QtCore.QSize(214, 82))
        DialogIpLookup.setWindowFilePath(_fromUtf8(""))
        DialogIpLookup.setSizeGripEnabled(True)
        self.verticalLayout = QtGui.QVBoxLayout(DialogIpLookup)
        self.verticalLayout.setObjectName(_fromUtf8("verticalLayout"))
        self.label = QtGui.QLabel(DialogIpLookup)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Fixed, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setObjectName(_fromUtf8("label"))
        self.verticalLayout.addWidget(self.label)
        self.lineEdit = QtGui.QLineEdit(DialogIpLookup)
        self.lineEdit.setInputMethodHints(QtCore.Qt.ImhNone)
        self.lineEdit.setAlignment(QtCore.Qt.AlignCenter)
        self.lineEdit.setObjectName(_fromUtf8("lineEdit"))
        self.verticalLayout.addWidget(self.lineEdit)
        self.labelResult = QtGui.QLabel(DialogIpLookup)
        sizePolicy = QtGui.QSizePolicy(QtGui.QSizePolicy.Expanding, QtGui.QSizePolicy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.labelResult.sizePolicy().hasHeightForWidth())
        self.labelResult.setSizePolicy(sizePolicy)
        self.labelResult.setAlignment(QtCore.Qt.AlignCenter)
        self.labelResult.setObjectName(_fromUtf8("labelResult"))
        self.verticalLayout.addWidget(self.labelResult)

        self.retranslateUi(DialogIpLookup)
        QtCore.QMetaObject.connectSlotsByName(DialogIpLookup)

    def retranslateUi(self, DialogIpLookup):
        DialogIpLookup.setWindowTitle(QtGui.QApplication.translate("DialogIpLookup", "Ip Lookup", None, QtGui.QApplication.UnicodeUTF8))
        self.label.setText(QtGui.QApplication.translate("DialogIpLookup", "Enter an IP address and press enter:", None, QtGui.QApplication.UnicodeUTF8))
        self.lineEdit.setInputMask(QtGui.QApplication.translate("DialogIpLookup", "000.000.000.000; ", None, QtGui.QApplication.UnicodeUTF8))
        self.labelResult.setText(QtGui.QApplication.translate("DialogIpLookup", "---", None, QtGui.QApplication.UnicodeUTF8))

class UtilityWidget(QtGui.QDialog):
  def __init__(self,parent):
    if parent == None:
      raise TypeError('parent must be set to a QWidget inherited object')
      return False
    #if not type(parent.agent.controller) == stem.control.Controller:
    #  raise TypeError('parent.agent.controller must be set to a stem.control.Controller instance')
    #  return False
    super(QtGui.QDialog, self).__init__(parent.MainWindow)
    self.parent = parent
    self.ui = Ui_DialogIpLookup()
    self.ui.setupUi(self)
    QtCore.QObject.connect(self.ui.lineEdit, QtCore.SIGNAL(_fromUtf8("returnPressed()")), self.lookupThatIp)
    self.re_validip = re.compile(r'^(([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})\.){3}([2][0-5][0-5]|[2][0-4][0-9]|1?[0-9]{1,2})$')
    self.show()
  def lookupThatIp(self):
    tmpip = str(self.ui.lineEdit.text())
    if not re.match(self.re_validip,tmpip):
      self.ui.labelResult.setText('(**not a valid ip**)')
    else:
      tmpresult = self.parent.cncSend( 'get_iplocation', tmpip )
      #tmpresult = self.parent.agent.controller.get_info('ip-to-country/%s' % tmpip )
      print tmpresult
      try:
        self.ui.labelResult.setText('(' + tmpresult + ') ' + digraphs[tmpresult])
      except Exception, e:
        self.ui.labelResult.setText('(' + tmpresult + ') ERROR:' + str(e))
  def closeEvent(self,event):
    self.ui.labelResult.setText('---')
    self.ui.lineEdit.setText('')
    event.accept()


if __name__ == "__main__":
    import sys
    app = QtGui.QApplication(sys.argv)
    DialogIpLookup = QtGui.QDialog()
    ui = Ui_DialogIpLookup()
    ui.setupUi(DialogIpLookup)
    DialogIpLookup.show()
    sys.exit(app.exec_())

