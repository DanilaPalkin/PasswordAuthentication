# Form implementation generated from reading ui file 'decrypt.ui'
#
# Created by: PyQt6 UI code generator 6.3.0
#
# WARNING: Any manual changes made to this file will be lost when pyuic6 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt6 import QtCore, QtGui, QtWidgets


class Ui_Form2(object):
    def setupUi(self, Form2):
        Form2.setObjectName("Form2")
        Form2.resize(400, 188)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Policy.Fixed, QtWidgets.QSizePolicy.Policy.Fixed)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(Form2.sizePolicy().hasHeightForWidth())
        Form2.setSizePolicy(sizePolicy)
        self.label = QtWidgets.QLabel(Form2)
        self.label.setGeometry(QtCore.QRect(20, 10, 361, 71))
        font = QtGui.QFont()
        font.setPointSize(14)
        self.label.setFont(font)
        self.label.setAlignment(QtCore.Qt.AlignmentFlag.AlignCenter)
        self.label.setObjectName("label")
        self.lineEdit = QtWidgets.QLineEdit(Form2)
        self.lineEdit.setGeometry(QtCore.QRect(10, 90, 380, 30))
        self.lineEdit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.lineEdit.setObjectName("lineEdit")
        self.pushButton = QtWidgets.QPushButton(Form2)
        self.pushButton.setGeometry(QtCore.QRect(10, 130, 125, 40))
        self.pushButton.setObjectName("pushButton")
        self.pushButton_2 = QtWidgets.QPushButton(Form2)
        self.pushButton_2.setGeometry(QtCore.QRect(260, 130, 125, 40))
        self.pushButton_2.setObjectName("pushButton_2")

        self.retranslateUi(Form2)
        QtCore.QMetaObject.connectSlotsByName(Form2)

    def retranslateUi(self, Form2):
        _translate = QtCore.QCoreApplication.translate
        Form2.setWindowTitle(_translate("Form2", "Расшифровать базу данных"))
        self.label.setText(_translate("Form2", "Пароль для расшифровывания\n"
"базы учётных записей"))
        self.pushButton.setText(_translate("Form2", "Ок"))
        self.pushButton_2.setText(_translate("Form2", "Отмена"))
