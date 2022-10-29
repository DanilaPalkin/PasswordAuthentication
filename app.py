import sys, os, fileinput, re
import layout, authwindow, users, decrypt
import enc
from PyQt6 import QtWidgets
from PyQt6.QtCore import Qt

class Decrypt(QtWidgets.QWidget, decrypt.Ui_Form2):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.decrypt)
        self.pushButton_2.clicked.connect(self.close)
        # Временный файл всё равно автоматически удаляется
        with open('db.txt', 'w') as f:
            f.write('ADMIN \t False False\n')
        #enc.encryption()

    def closeEvent(self, event):
        enc.encryption()
        os.remove('db.txt')
    
    def decrypt(self):
        if self.lineEdit.text() == enc.password:
            self.hide()
            enc.decryption()
            self.dialog = App()
            self.dialog.show()
        else:
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Ошибка', 'Неправильный пароль')


class UsersWindow(QtWidgets.QWidget, users.Ui_Form1):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.save)
        self.load()

    def load(self):
        row = 0
        with open('db.txt', 'r') as f:
            for user in f:
                x = re.split(' |\n', user)
                self.tableWidget.setRowCount(row + 1)
                self.tableWidget.setItem(row, 0, QtWidgets.QTableWidgetItem(x[0]))
                self.tableWidget.setCellWidget(row, 1, QtWidgets.QCheckBox())

                if x[2] == 'True':
                    self.tableWidget.cellWidget(row, 1).setChecked(True)
                self.tableWidget.setCellWidget(row, 2, QtWidgets.QCheckBox())
                if x[3] == 'True':
                    self.tableWidget.cellWidget(row, 2).setChecked(True)

                self.tableWidget.item(row, 0).setFlags(Qt.ItemFlag(0))
                row += 1
        self.tableWidget.resizeColumnsToContents()
    
    def save(self):
        row = 0
        with fileinput.FileInput('db.txt', inplace=True) as f:
                for user in f:
                    # Разобьём строку на список из логина и пароля
                    x = re.split(' |\n', user)
                    # Не позволим админу забанить самого себя
                    if x[0] == 'ADMIN':
                        print(user.replace(user, f'{x[0]} {x[1]} False {self.tableWidget.cellWidget(row, 2).isChecked()}'))
                    else:
                        print(user.replace(user, f'{x[0]} {x[1]} {self.tableWidget.cellWidget(row, 1).isChecked()} {self.tableWidget.cellWidget(row, 2).isChecked()}'))
                    row += 1
        self.close()


class AuthWindow(QtWidgets.QDialog, authwindow.Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.userCredentials)

    def check(self):
        if not(self.lineEdit_3.text() and self.lineEdit_4.text()) and not self.lineEdit.isEnabled():
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Не все поля заполнены')
            return 1
        if self.lineEdit.text() == '':
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Укажите логин')
            return 1
        if ' ' in self.lineEdit.text():
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Логин не может содержать пробел')
            return 1
        if ' ' in self.lineEdit_3.text() or ' ' in self.lineEdit_4.text():
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Пароль не может содержать пробел')
            return 1
        return 0

    def passwordCheck(self, x):
        chars = set(':+-*/^%')
        if (x[3] == 'True') and not any((c in chars) for c in self.lineEdit_3.text()):
            return 1
        return 0
    
    def userCredentials(self):
        if(self.check() == 1):
            return
        flag = 0
        # Создание нового пользователя
        if self.lineEdit.isEnabled():
            with open('db.txt', 'r') as f:
                for user in f:
                    x = user.split(' ')
                    if x[0] == self.lineEdit.text():
                        QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Ошибка', 'Пользователь с таким логином уже существует')
                        f.close()
                        return
            with open('db.txt', 'a') as f:
                f.write(f'{self.lineEdit.text()} \t False False\n')
            flag = 1
        # Смена пароля
        else:
            with fileinput.FileInput('db.txt', inplace=True) as f:
                for user in f:
                    # Разобьём строку на список из логина и пароля
                    x = re.split(' |\n', user)
                    if(self.lineEdit_2.isEnabled()):
                        if(x[0] == self.lineEdit.text()) and (self.lineEdit_3.text() == self.lineEdit_4.text()) and (self.lineEdit_2.text() == x[1]):
                            if (self.passwordCheck(x) == 0):
                                print(user.replace(user, f'{self.lineEdit.text()} {self.lineEdit_3.text()} {x[2]} {x[3]}'))
                                # Использую здесь флаг, чтобы понять, выполнилось ли хоть раз условие
                                flag = 1
                            else:
                                print(user, end='')
                                flag = 2
                        else:
                            print(user, end='')
                    else:
                        # При входе пользователя с пустым паролем не будет
                        # сравниваться старый пароль с новым
                        if(x[0] == self.lineEdit.text()) and (self.lineEdit_3.text() == self.lineEdit_4.text()):
                            if (self.passwordCheck(x) == 0):
                                print(user.replace(user, f'{self.lineEdit.text()} {self.lineEdit_3.text()} {x[2]} {x[3]}'))
                                # Использую здесь флаг, чтобы понять, выполнилось ли хоть раз условие
                                flag = 1
                            else:
                                print(user, end='')
                                flag = 2
                        else:
                            print(user, end='')
        if flag == 0:
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Пароли не совпадают или введён неправильный старый пароль')
        elif flag == 2:
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Пароль должен содержать один из следующих символов: :+-*/^%')
        else:
            self.close()


class App(QtWidgets.QMainWindow, layout.Ui_MainWindow):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
        self.pushButton.clicked.connect(self.entrance)
        self.pushButton_2.clicked.connect(self.login)
        self.pushButton_3.clicked.connect(self.auth)
        self.pushButton_4.clicked.connect(self.auth)
        self.pushButton_5.clicked.connect(self.users)
        self.pushButton_6.clicked.connect(self.logout)
        self.pushButton_7.clicked.connect(self.about)
    
    def closeEvent(self, *args, **kwargs):
        super(QtWidgets.QMainWindow, self).closeEvent(*args, **kwargs)
        enc.encryption()
        os.remove('db.txt')

    login = ''
    password = ''
    
    def auth(self, flag):
        self.lineEdit.clear()
        self.lineEdit_2.clear()
        self.dialog = AuthWindow()
        self.dialog.setModal(True)
        button = self.sender()
        if button.text() == 'Смена пароля':
            self.dialog.lineEdit.setDisabled(True)
            self.dialog.lineEdit.setText(self.login)
        if button.text() == 'Войти':
            self.dialog.lineEdit.setDisabled(True)
            self.dialog.lineEdit_2.setDisabled(True)
            self.dialog.lineEdit.setText(self.login)
            if flag == 1:
                self.dialog.lineEdit_2.setDisabled(False)
        if button.text() == 'Новый пользователь':
            self.dialog.lineEdit.setDisabled(False)
            self.dialog.lineEdit_2.setDisabled(True)
            self.dialog.lineEdit_3.setDisabled(True)
            self.dialog.lineEdit_4.setDisabled(True)
        self.dialog.show()
    
    def login(self):
        # Очередной флаг для проверки существования пользователя с заданным именем и паролем
        flag = False
        self.login = self.lineEdit.text()
        self.password = self.lineEdit_2.text()
        chars = set(':+-*/^%')
        with open('db.txt', 'r') as f:
            for user in f:
                # Разобьём строку на список из логина и пароля
                x = re.split(' |\n', user)

                # Если пользователь с пустым паролем
                if (x[0] == self.login) and (x[1] == '\t'):
                    flag = True
                    if (x[2] == 'True'):
                        QtWidgets.QMessageBox.critical(QtWidgets.QMessageBox(), 'Ошибка', 'Вы были заблокированы администратором')
                    else:
                        self.auth(0)

                if (x[0] == self.login) and (x[1] == self.password) and (x[2] == 'False'):
                    if(x[3] == 'True'):
                        if not any((c in chars) for c in x[1]):
                            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'На пароль были наложены ограничения. Смените пароль')
                            self.auth(1)
                            return
                    self.label.setText(f'Привет, {self.login}!')
                    self.label.setHidden(False)
                    self.lineEdit.setHidden(True)
                    self.lineEdit_2.setHidden(True)
                    self.pushButton_2.setHidden(True)
                    self.pushButton_3.setHidden(False)
                    self.pushButton_4.setHidden(False)
                    self.pushButton_5.setHidden(False)
                    self.pushButton_6.setHidden(False)
                    flag = True
                if (x[0] == self.login) and (x[1] == self.password) and (x[2] == 'True'):
                    QtWidgets.QMessageBox.critical(QtWidgets.QMessageBox(), 'Ошибка', 'Вы были заблокированы администратором')
                    flag = True

        if (self.login == 'ADMIN'):
            self.pushButton_4.setEnabled(True)
            self.pushButton_5.setEnabled(True)
        else:
            self.pushButton_4.setEnabled(False)
            self.pushButton_5.setEnabled(False)

        if flag == False:
            QtWidgets.QMessageBox.warning(QtWidgets.QMessageBox(), 'Внимание', 'Неправильный логин или пароль')

    def entrance(self):
        self.pushButton.setHidden(True)
        self.lineEdit.setHidden(False)
        self.lineEdit_2.setHidden(False)
        self.pushButton_2.setHidden(False)
        self.pushButton_7.setHidden(True)

    def logout(self):
        self.label.setHidden(True)
        self.pushButton.setHidden(False)
        self.lineEdit.setHidden(True)
        self.lineEdit.clear()
        self.lineEdit_2.setHidden(True)
        self.lineEdit_2.clear()
        self.pushButton_2.setHidden(True)
        self.pushButton_3.setHidden(True)
        self.pushButton_4.setHidden(True)
        self.pushButton_5.setHidden(True)
        self.pushButton_6.setHidden(True)
        self.pushButton_7.setHidden(False)

    def about(self):
        QtWidgets.QMessageBox.information(QtWidgets.QMessageBox(), 'Вариант 14', 'Работу выполнил студент группы\nИДБ-19-02 Палкин Данила')

    def users(self):
        self.dialog = UsersWindow()
        self.dialog.show()


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = Decrypt()
    window.show()
    app.exec()

if __name__ == '__main__':
    main()