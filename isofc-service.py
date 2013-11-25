#!/usr/bin/env python3.2
## This file is part of the isofc application, released under
## GNU General Public License, Version 3.0
## See file COPYING for details.
##
## Author: Klementyev Mikhail <jollheef@riseup.net>
#

import sys
import os
import subprocess
import pyudev
import time
import simplejson as json
import re
from threading import Thread, Lock, current_thread
from gi.repository import Gtk, GObject
from os.path import dirname, abspath
from sconfparser import SConfParser

StatusMsg = {
    'Free': 'Свободен',
    'Connected': 'Подключен',
    'Copying': 'Идет копирование',
    # Warn: all *Error must contain 'Error' value (for ex.: 'Ошибка')
    'Error': 'Ошибка',
    'MountError': 'Ошибка монтирования',
    'CopyError': 'Ошибка копирования',
    'UmountError': 'Ошибка размонтирования',
    'Connecting': 'Соединение с сервером',
    'ConnectingError': 'Ошибка соединения с сервером',
    'AuthFileNotFoundError': 'Ошибка: Нет файла аутентификации',
    'AuthSmbError': 'Ошибка: проверьте логин и пароль.',
    'MoreOneLogin': 'Ошибка: логин уже используется',
    'WrongAuthFileError': 'Ошибка: Неверный файл аутентификации',
    'TransferError': 'Ошибка передачи файлов',
    'DisconnectPlease': 'Можно извлекать',
    'DisconnectAddition': ', извлеките устройство',
}

StatusClrs = {
    'Normal': 'white',
    'Error': 'red',
    'Copying': 'yellow',
    'DisconnectPlease': 'green',
}

for PortNum in range(1, 8):
    Port = "Port" + str(PortNum) + "Status"
    exec(Port + ' = """<span foreground="' + StatusClrs['Normal']
         + '" size="x-large">' + StatusMsg['Free'] + '</span>"""')


def Log(message):
    global config
    log_message = str(str(time.strftime("[%d %b %Y %H:%M:%S] ("))
                      + current_thread().name + ") " + str(message))
    print(log_message)
    with open(config.log_filepath, "a+") as f:
        f.write(log_message + "\n")


def DeviceHandlerExceptionWrapper(action, device):
    try:
        DeviceHandler(action, device)
    except Exception as e:
        Log(str(e))


def DeviceHandler(action, device):
    getstatusoutput(["xset", "-dpms"], False)
    getstatusoutput(["xset", "+dpms"], False)
    try:
        Log("Port: " + str(Port(device)) + ", "
            + "Action: " + str(action) + ", "
            + "DEVNAME: " + str(device['DEVNAME']) + ", "
            + "ID_SERIAL: " + str(device['ID_SERIAL']) + " ")
    except:
        Log("Fail on Port: " + str(Port(device)) + ", "
            + "Action: " + str(action))
        return None
    global Clients, Ports, ExitFlag
    PortLock = "Port" + str(Port(device)) + "Lock"
    exec('global ' + PortLock)
    if str(action) == "add":
        if len(str(device.device_node)) == 8:
            if sum(1 for _ in device.children) != 0:
                Log(str(device.device_node)
                    + " is not mount (partition table)")
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
        if Credentials[0] is not True:
            StatusSet(device, Credentials[1],
                      StatusClrs['Error'])
            if Credentials[1] == StatusMsg['WrongAuthFileError']:
                Ports.append(Port(device))
        else:
            Log(str(device.device_node) + ", "
                + "Login: " + Credentials[1] + ", "
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
                StatusSet(device, StatusMsg['Connecting'],
                          StatusClrs['Normal'])
                smb_auth_result = SmbAuthp(Credentials)
                if smb_auth_result == 0:
                    if not Transfer(device,
                                    usbdirectory,
                                    Credentials):
                        StatusSet(device,
                                  StatusMsg['TransferError'],
                                  StatusClrs['Error'])
                    else:
                        Log(str(device.device_node) + " All good")
                elif smb_auth_result == 256:  # timeout
                    StatusSet(device,
                              StatusMsg['ConnectingError'],
                              StatusClrs['Error'])
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
        if len(Ports) == 0 and ExitFlag:
            ExitFlag = False
            try:
                global Gtk
                Log("Gtk main_quit")
                Gtk.main_quit()
            except:
                ExitFlag = True


def SmbNetFsInit(SmbDirectory):
    try:
        os.makedirs(SmbDirectory, exist_ok=True)
    except OSError as e:
        if e.errno == 17:
            SmbNetFsClose(SmbDirectory)
        else:
            raise
    retcode, output = getstatusoutput(["/usr/bin/smbnetfs",
                                       SmbDirectory], False)
    Log("Smbnetfs init: " + "retcode: " + str(retcode) + ", "
        + "output: " + output)
    return output == ""


def SmbNetFsClose(SmbDirectory):
    return getstatusoutput(["/bin/fusermount", "-u",
                            SmbDirectory], False)[0] == 0


def SmbAuthp(Credentials):
    global config
    Login, Password = Credentials[1], Credentials[2]
    if not re.match('^[a-zA-Z0-9]*$', Login):
        Log("login contain unacceptable symbols: " + str(Login))
        return False
    return getstatusoutput(["/bin/ls", config.smbnetfs_directory
                            + "/" + Login
                            + ":" + Password
                            + "@" + config.server_ip + "/"
                            + Login], False, timeout=20)[0]


def base64p(string):
    if re.match('^(?:[A-Za-z0-9+/]{4})*'
                + '(?:[A-Za-z0-9+/]{2}=='
                + '|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})$', string):
        return True
    else:
        return False


def Decrypt(ciphertext):
    global config
    if not os.path.isfile(config.private_key_path):
        Log("Private key not found")
        return 'Error'
    if not base64p(ciphertext):
        Log(".isofc_credentials is not base64, Ciphertext = '"
            + str(ciphertext) + "'")
        return 'Error'
    retcode, opentext = getstatusoutput(
        "echo " + ciphertext + "|base64 -d|openssl rsautl -inkey "
        + config.private_key_path + " -decrypt")
    Log("Retcode(decrypt): " + str(retcode))
    if retcode == 0:
        return opentext
    else:
        return 'Error'


def CheckAuth(device, usbdirectory):
    try:
        with open(usbdirectory + "/.isofc_credentials", "r") as file:
            data = file.read().replace('\n', '')
    except IOError as exc:
        if exc.errno == 2:
            return [False, StatusMsg['AuthFileNotFoundError']]
        else:
            raise
    Credentials = Decrypt(data)
    if Credentials == 'Error':
        return [False, StatusMsg['WrongAuthFileError']]
    try:
        Credentials = json.loads(Credentials)
        serial = device['ID_SERIAL_SHORT']
    except:
        return [False, StatusMsg['WrongAuthFileError']]
    if serial != Credentials['Serial']:
        Log("Serial ID in credentials (" + str(serial)
            + ") is not equal serial ID in usb device ("
            + str(Credentials['Serial']) + ")")
        return [False, StatusMsg['WrongAuthFileError']]
    return [True, Credentials['Login'], Credentials['Password'],
            serial]


def StatusSet(device, message, color):
    Log("Change status " + str(device.device_node) + " to "
        + str(message) + " with " + str(color) + " color")
    for PortNum in range(1, 8):
        _Port = "Port" + str(PortNum) + "Status"
        exec('global ' + _Port)
    exec('Port' + str(Port(device)) + 'Status = """'
         + '<span foreground="' + color + '" size="x-large">'
         + message + '</span>"""', locals(), globals())


def Status(device):
    for PortNum in range(1, 8):
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


def directoryList(path, regex='.*'):
    return [o for o in os.listdir(path)
            if os.path.isdir(os.path.join(path, o))
            and re.match(regex, o)]


def get_in_out(root_path):
    ins = directoryList(root_path, '^(?i)in$')
    outs = directoryList(root_path, '^(?i)out$')
    ins.sort(reverse=True)
    outs.sort(reverse=True)
    try:
        _in = ins[0]
    except IndexError:
        _in = "in"
    try:
        _out = outs[0]
    except IndexError:
        _out = "out"
    return (root_path + "/" + _in + "/",
            root_path + "/" + _out + "/")


def update_files(usb_dir, files):
    global ExitFlag
    flag = False
    usb_dir = "/" + usb_dir + "/"
    for f in files:
        getstatusoutput("rm " + usb_dir + f)
        if getstatusoutput("stat " + usb_dir + f + ".gpg")[0] != 0:
            Log("file " + f + ".gpg" + " not found")
            continue
        if gpg_decrypt(usb_dir + f + ".gpg"):
            Log("Start update " + f)
            getstatusoutput("cp " + usb_dir + f + " "
                            + dirname(abspath(__file__))
                            + "/" + f,
                            logging=True)
            getstatusoutput("cp " + dirname(abspath(__file__))
                            + "/" + f
                            + " " + dirname(abspath(__file__))
                            + "/" + f + ".BACKUP",
                            logging=True)
            getstatusoutput("chmod 755 "
                            + dirname(abspath(__file__))
                            + "/" + f,
                            logging=True)
            getstatusoutput("rm " + usb_dir + f,
                            logging=True)
            getstatusoutput("mv " + usb_dir + f + ".gpg "
                            + usb_dir + f + ".gpg.OLD",
                            logging=True)
            flag = True
    if flag:
        Log("Finish update: exit (wait for free all ports)")
        ExitFlag = True


def gpg_decrypt(path_to_file):
    orig_file = path_to_file.replace('.gpg', '')
    getstatusoutput("rm " + orig_file)
    status, output = getstatusoutput("gpg " + path_to_file)
    Log("Status: " + str(status) + "; " + output.replace('\n', '; '))
    if status == 0 and re.findall('ID ' + config.admin_rsa_id,
                                  output.splitlines()[0]):
        Log("Gpg verify: true sign")
        return orig_file
    else:
        Log("Gpg verify: bad sign")
        return False


def do_admin_work(usb_in):
    global config
    update_files(usb_in, ["isofc-service.py",
                          "isofc-service.conf",
                          "isofc-service.glade"])
    getstatusoutput(["/bin/cp",
                     config.log_filepath,
                     usb_in + "/"],
                    shell=False)

def Transfer(device, UsbDirectory, Credentials):
    Log("Start transfer")
    global config
    Login, Password = Credentials[1], Credentials[2]
    UserDirectory = str(config.smbnetfs_directory + "/" + Login
                        + ":" + Password
                        + "@" + config.server_ip + "/" + Login)
    smbIn, smbOut = get_in_out(UserDirectory)
    usbIn, usbOut = get_in_out(UsbDirectory)
    if Status(device) != StatusMsg['Free']:
        StatusSet(device, StatusMsg['Copying'],
                  StatusClrs['Copying'])
    for _dir in [smbIn, smbOut, usbIn, usbOut]:
        try:
            os.makedirs(_dir, exist_ok=True)
        except Exception as e:
            if e.errno != 17:
                Log(str(e))
            pass
    try:
        if Login == config.admin:
            Log("Admin login: " + Login)
            do_admin_work(usbIn)
    except Exception as e:
        Log("Error while admin work: " + str(e))
    retcodeU = 0
    retcodeD = 0
    Log("List of smb/Out:")
    list_files(smbOut)
    Log("List of usb/Out:")
    list_files(usbOut)
    try:
        for directory in [smbOut, smbIn, usbOut, usbIn]:
            if os.path.islink(directory):
                Log(str(directory) + " is symlink")
                return False
        for _dir in os.listdir(smbOut):
            if getstatusoutput(["/bin/cp", "-R",
                                smbOut + _dir, usbIn + _dir],
                               shell=False)[0] == 0:
                retcodeU = getstatusoutput(["/bin/rm",
                                            smbOut + _dir, "-rf"],
                                           shell=False)[0]
            else:
                retcodeU = 1
        for _dir in os.listdir(usbOut):
            if getstatusoutput(["/bin/cp", "-R",
                                usbOut + _dir, smbIn + _dir],
                               shell=False)[0] == 0:
                retcodeD = getstatusoutput(["/bin/rm",
                                            usbOut + _dir, "-rf"],
                                           shell=False)[0]
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
                      Status(device)
                      + StatusMsg['DisconnectAddition'],
                      StatusClrs['Error'])
        else:
            StatusSet(device, StatusMsg['DisconnectPlease'],
                      StatusClrs['DisconnectPlease'])
    return retval


def getstatusoutput(cmd, shell=True, timeout=0, logging=False):
    """Return (status, output) of executing cmd in a shell."""
    """This new implementation should work on all platforms."""
    pipe = subprocess.Popen(cmd, shell=shell,
                            universal_newlines=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT)
    deadline = time.time()+timeout
    if timeout:
        while pipe.poll() is None and time.time() < deadline:
            time.sleep(.250)
        if pipe.poll() is None:
            pipe.terminate()
            return 256, ""
    sts = pipe.wait()
    output = str.join("", pipe.stdout.readlines())
    if sts is None:
        sts = 0
    if logging and (sts != 0):
        Log(output)
    return sts, output


class MainWindow(Gtk.Window):
    def __init__(self):
        global config
        self.builder = Gtk.Builder()
        self.builder.add_from_file("isofc-service.glade")
        self.window = self.builder.get_object("MainWindow")
        self.window.show_all()
        x, y = map(int, config.screen_resolution.split('x'))
        self.window.resize(x, y)
        self.window.connect("delete-event", Gtk.main_quit)

        self.timeout_id = GObject.timeout_add(1000,
                                              self.on_timeout,
                                              None)

        for PortNum in range(1, 8):
            _Port = "Port" + str(PortNum) + "Status"
            exec('global ' + _Port)

    def on_timeout(self, user_data):
        for PortNum in range(1, 8):
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
            target=DeviceHandlerExceptionWrapper,
            args=[action, device]).start())

    def run(self):
        self.observer.start()
        Log(self.observer)

try:
    config = SConfParser(dirname(abspath(__file__)) + "/isofc-service.conf")

    Log("isofc-service.py started")

    GObject.threads_init()

    ExitFlag = False
    ClientsLock = Lock()
    Clients = []
    for PortNum in range(1, 8):
        exec("Port" + str(PortNum) + "Lock" + ' = Lock()')
    Ports = []
    if not SmbNetFsInit(config.smbnetfs_directory):
        Log("Cannot create smbnetfs")
        SmbNetFsClose(config.smbnetfs_directory)
        sys.exit(1)

    win = MainWindow()

    thread = MainThread(win)
    thread.start()
    Gtk.main()

    thread.observer.stop()
    if not SmbNetFsClose(config.smbnetfs_directory):
        Log("Cannot umount smbnetfs, check this manually")
    Log(thread.observer)
    sys.exit(0)

except Exception as e:
    Log("Error: " + str(e))
