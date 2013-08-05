#!/usr/bin/env python3
## This file is part of the isofc application, released under
## GNU General Public License, Version 3.0
## See file COPYING for details.
##
## Author: Klementyev Mikhail <jollheef@riseup.net>
#

import sys, os, subprocess
import pyudev
import time
import simplejson as json
import re
from threading import Thread, Lock, current_thread 
from gi.repository import Gtk, GObject

StatusMsg = {
    'Free' : 'Свободен',
    'Connected' : 'Подключен',
    'Copying' : 'Идет копирование',
    # Warn: all *Error must contain 'Error' value (for ex.: 'Ошибка')
    'Error' : 'Ошибка',
    'MountError' : 'Ошибка монтирования',
    'CopyError' : 'Ошибка копирования',
    'UmountError': 'Ошибка размонтирования',
    'AuthFileNotFoundError' : 'Ошибка: Нет файла аутентификации',
    'AuthSmbError' : 'Ошибка: проверьте логин и пароль.',
    'MoreOneLogin' : 'Ошибка: логин уже используется',
    'WrongAuthFileError' : 'Ошибка: Неверный файл аутентификации',
    'TransferError': 'Ошибка передачи файлов',
    'DisconnectPlease' : 'Можно извлекать',
    'DisconnectAddition' : ', извлеките устройство',
}

StatusClrs = {
    'Normal' : 'white',
    'Error' : 'red',
    'Copying' : 'yellow',
    'DisconnectPlease' : 'green',
}

for PortNum in range(1,8):
    Port = "Port" + str(PortNum) + "Status"
    exec(Port + ' = """<span foreground="' + StatusClrs['Normal'] \
         + '" size="x-large">' + StatusMsg['Free'] + '</span>"""')
    
def Log(message):
    print(str(time.strftime("[%d %b %Y %H:%M:%S] (")) + \
          current_thread().name + ") " + str(message))

def DeviceHandler(action, device):
    try:
        Log("Port: " + str(Port(device)) + ", "\
            + "Action: " + str(action) + ", " \
            + "DEVNAME: " + str(device['DEVNAME']) + ", " \
            + "ID_SERIAL: " + str(device['ID_SERIAL']) + " ")
    except:
        Log("Fail on Port: " + str(Port(device)) + ", " \
            + "Action: " + str(action))
        return None
    global Clients, Ports
    PortLock = "Port" + str(Port(device)) + "Lock"
    exec('global ' + PortLock)
    if str(action) == "add":
        if len(str(device.device_node)) == 8:
            if sum(1 for _ in device.children) != 0:
                Log(str(device.device_node) + " is not mount (partition table)")
                return None
        exec(PortLock + '.acquire()', locals(), globals())
        if list(filter(lambda pt: pt == Port(device), Ports)):
            Log(str(device.device_node) + " will not be served")
            exec(PortLock + '.release()', locals(), globals())
            return None
        StatusSet(device, StatusMsg['Connected'],
                  StatusClrs['Normal'])
        retval, usbdirectory = UsbMount(device)
        if retval != 0:
            Log("Cannot mount " + str(device.device_node))
            if Status(device) != StatusMsg['Free']:
                StatusSet(device, StatusMsg['MountError'],
                          StatusClrs['Error'])
            try:
                exec(PortLock + '.release()', locals(), globals())
            except:
                pass
            return None
        Log(str(device.device_node) + " mounted")
        Credentials = CheckAuth(device, usbdirectory)
        if Credentials[0] != True:
            StatusSet(device, Credentials[1],
                      StatusClrs['Error'])
            if Credentials[1] == StatusMsg['WrongAuthFileError']:
                Ports.append(Port(device))
        else:
            Log(str(device.device_node) + ", " \
                + "Login: " + Credentials[1] + ", " \
                + "Serial: " + Credentials[3])
            Ports.append(Port(device))
            exec(PortLock + '.release()', locals(), globals())
            ClientsLock.acquire()
            if list(filter(lambda cl: cl[1] == Credentials[1],
                           Clients)):
                StatusSet(device, StatusMsg['MoreOneLogin'],
                          StatusClrs['Error'])
                ClientsLock.release()
            else:
                Clients.append([device.device_node, Credentials[1]])
                ClientsLock.release()
                if SmbAuthp(Credentials):
                    if not Transfer(device,
                                    usbdirectory,
                                    Credentials):
                        StatusSet(device,
                                  StatusMsg['TransferError'],
                                  StatusClrs['Error'])
                    else:
                        Log(str(device.device_node) + " All good")
                else:
                    StatusSet(device,
                              StatusMsg['AuthSmbError'],
                              StatusClrs['Error'])
                    Log(str(device.device_node) + ", wrong credentials")
        if UsbUmount(device) != 0:
            Log(str(device.device_node) + ", failed umount")
            StatusSet(device, StatusMsg['UmountError'],
                      StatusClrs['Error'])
        try:
            exec(PortLock + '.release()', locals(), globals())
        except:
            pass
    if str(action) == "remove":
        Clients = list(filter(
            lambda cl: cl[0] != device.device_node, Clients))
        Ports = list(filter(
            lambda pt: pt != Port(device), Ports))
        try:
            exec(PortLock + '.release()', locals(), globals())
        except:
            pass
        StatusSet(device, StatusMsg['Free'],
                  StatusClrs['Normal'])

def SmbNetFsInit(SmbDirectory):
    os.makedirs(SmbDirectory, exist_ok=True)
    retcode, output = getstatusoutput(["/usr/bin/smbnetfs",
                                       SmbDirectory], False)
    Log("Smbnetfs init: " + "retcode: " + str(retcode) + ", " \
        + "output: " + output)
    return output == ""

def SmbNetFsClose(SmbDirectory):
    return getstatusoutput(["/bin/fusermount", "-u",
                            SmbDirectory], False)[0] == 0

def SmbAuthp(Credentials):
    global SmbDirectory
    Login, Password = Credentials[1], Credentials[2]
    if not re.match('^\d{2}[a-zA-Z]{2}\d{3}$', Login):
        Log("login contain unacceptable symbols")
        return False
    return getstatusoutput(["/bin/ls", SmbDirectory + "/" + Login \
                            + ":" + Password + "@172.16.40.2/" \
                            + Login], False)[0] == 0
    
def base64p(string):
    if re.match('^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$', string):
        return True
    else:
        return False

def Decrypt(ciphertext, path_to_private_key = "/home/michael/dev/sofc/private_key"):
    if not base64p(ciphertext):
        Log(".isofc_credentials is not base64, Ciphertext = '" \
            + str(ciphertext) + "'")
        return 'Error'
    retcode, opentext =  getstatusoutput(
        "echo " + ciphertext + "|base64 -d|openssl rsautl -inkey " \
        + path_to_private_key + " -decrypt")
    Log("Retcode(decrypt): " + str(retcode))
    if retcode == 0:
        return opentext
    else:
        return 'Error'

def CheckAuth(device, usbdirectory):
    try:
        with open (usbdirectory + "/.isofc_credentials", "r") as file:
            data=file.read().replace('\n', '')
    except FileNotFoundError:
        return [False, StatusMsg['AuthFileNotFoundError']]
    Credentials = Decrypt(data)
    if Credentials == 'Error':
        return [False, StatusMsg['WrongAuthFileError']]
    Credentials = json.loads(Credentials) 
    serial = device['ID_SERIAL_SHORT']
    if serial != Credentials['Serial']:
        return [False, StatusMsg['WrongAuthFileError']]
    return [True, Credentials['Login'], Credentials['Password'],
            serial]

def StatusSet(device, message, color):
    Log("Change status " + str(device.device_node) + " to " \
        + str(message) + " with " + str(color)  + " color")
    for PortNum in range(1,8):
        _Port = "Port" + str(PortNum) + "Status"
        exec('global ' + _Port)
    exec('Port' + str(Port(device)) + 'Status = """' \
         + '<span foreground="' + color + '" size="x-large">' \
         + message + '</span>"""', locals(), globals())

def Status(device):
    for PortNum in range(1,8):
        _Port = "Port" + str(PortNum) + "Status"
        exec('global ' + _Port)
    return re.sub('<[^>]*>', '',
                  eval('Port' + str(Port(device)) + 'Status'))

def list_files(startpath):
    for root, dirs, files in os.walk(startpath):
        level = root.replace(startpath, '').count(os.sep)
        indent = ' ' * 4 * (level)
        Log('{}{}/'.format(indent, os.path.basename(root)))
        subindent = ' ' * 4 * (level + 1)
        for f in files:
            Log('{}{}'.format(subindent, f))

def Transfer(device, UsbDirectory, Credentials):
    global SmbDirectory
    Login, Password = Credentials[1], Credentials[2]
    UserDirectory = SmbDirectory + "/" + Login + ":" + Password \
                    + "@172.16.40.2/" + Login
    smbIn = UserDirectory + "/in/"
    smbOut = UserDirectory + "/out/"
    usbIn = UsbDirectory + "/in/"
    usbOut = UsbDirectory + "/out/"
    if Status(device) != StatusMsg['Free']:
        StatusSet(device, StatusMsg['Copying'],
                  StatusClrs['Copying'])
    for _dir in [ smbIn, smbOut, usbIn, usbOut ]:
        try:
            os.makedirs(_dir, exist_ok=True)
        except:
            Log(str(sys.exc_info()[1]))
            pass
    retcodeU = 0
    retcodeD = 0
    Log("List of smb/Out:")
    list_files(smbOut)
    Log("List of usb/Out:")
    list_files(usbOut)
    try:
        for directory in [ smbOut, smbIn, usbOut, usbIn ]:
            if os.path.islink(directory):
                Log(str(directory) + " is symlink")
                return False
        for _dir in os.listdir(smbOut):
            if getstatusoutput(["/bin/cp", "-R",
                                smbOut + _dir, usbIn + _dir],
                               _shell=False)[0] == 0:
                retcodeU = getstatusoutput(["/bin/rm",
                                            smbOut + _dir, "-rf"],
                                           _shell=False)[0]
            else:
                retcodeU = 1
        for _dir in os.listdir(usbOut):
            if getstatusoutput(["/bin/cp", "-R",
                                usbOut + _dir, smbIn + _dir],
                               _shell=False)[0] == 0:
                retcodeD = getstatusoutput(["/bin/rm",
                                            usbOut + _dir, "-rf"],
                                           _shell=False)[0]
            else:
                retcodeD = 1
    except:
        Log(str(sys.exc_info()[1]))
        pass
    return retcodeU + retcodeD == 0
    
def Port(device):
    return {
        '4': 7,
        '3': 6,
        '7': 5,
        '2': 4,
        '1': 3,
        '6': 2,
        '5': 1,
    }[str(device.device_path)[46]]

def UsbMount(device):
    retval, output = getstatusoutput("pmount " + device.device_node)
    return [retval, re.sub(r'dev', 'media', device.device_node)]

def UsbUmount(device):
    retval, output = getstatusoutput("pumount " + device.device_node)
    if Status(device) != StatusMsg['Free']:
        if Status(device).find(StatusMsg['Error']) >= 0:
            StatusSet(device,
                      Status(device) \
                      + StatusMsg['DisconnectAddition'],
                      StatusClrs['Error'])
        else:
            StatusSet(device, StatusMsg['DisconnectPlease'],
                      StatusClrs['DisconnectPlease'])
    return retval

def getstatusoutput(cmd, _shell=True): 
    """Return (status, output) of executing cmd in a shell."""
    """This new implementation should work on all platforms."""
    pipe = subprocess.Popen(cmd, shell=_shell,
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    output = str.join("", pipe.stdout.readlines()) 
    sts = pipe.wait()
    if sts is None:
        sts = 0
    return sts, output

class MainWindow(Gtk.Window):
    def __init__(self):
        self.builder = Gtk.Builder()
        self.builder.add_from_file("isofc-service.glade")
        self.window = self.builder.get_object("MainWindow")
        self.window.show_all()
        self.window.connect("delete-event", Gtk.main_quit)

        self.timeout_id = GObject.timeout_add(1000,
                                              self.on_timeout,
                                              None)

        for PortNum in range(1,8):
            _Port = "Port" + str(PortNum) + "Status"
            exec('global ' + _Port)

    def on_timeout(self, user_data):
        for PortNum in range(1,8):
            Port = "Port" + str(PortNum) + "Status"
            self.builder.get_object(Port).set_markup(eval(Port))
        return True    

class MainThread(Thread):
    def __init__(self, _win):
        super(MainThread, self).__init__()
        self.win = _win
        self.quit = False

    context = pyudev.Context()
    monitor = pyudev.Monitor.from_netlink(context)
    monitor.filter_by('block')
    observer = pyudev.MonitorObserver(
        monitor,
        lambda action, device: Thread(
            target=DeviceHandler,
            args=[action, device]).start())

    def run(self):
        self.observer.start()
        Log(self.observer)

Log("isofc-service.py started")

GObject.threads_init()

ClientsLock = Lock()
Clients = []
for PortNum in range(1,8):
    exec("Port" + str(PortNum) + "Lock" + ' = Lock()')
Ports = []
SmbDirectory = "/tmp/isofc-smbnetfs"
if not SmbNetFsInit(SmbDirectory):
    Log("Cannot create smbnetfs")
    SmbNetFsClose(SmbDirectory)
    sys.exit(1)

win = MainWindow()

thread = MainThread(win)
thread.start()
Gtk.main()

thread.observer.stop()
if not SmbNetFsClose(SmbDirectory):
    Log("Cannot umount smbnetfs, check this manually")
Log(thread.observer)
sys.exit(0)
