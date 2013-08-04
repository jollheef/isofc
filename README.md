ISOFC
=====

### Deb-based(Debian, Ubuntu etc.)

    $ sudo apt-get install git ironpython
    $ git clone https://github.com/jollheef/isofc/
    $ ipy ./isofc/isofc-client.ipy

### Windows

Скачиваем и устанавливаем [ironpython](http://ironpython.net/download/)

Нажимаем Win + R (Пуск -> Выполнить), выполняем

    C:\Program Files (x86)\IronPython 2.7\ipy.exe \путь\к\isofc-client.ipy

#### Компиляция под Windows как автономное приложение

Как прикрутить иконку читать [тут](http://stackoverflow.com/questions/4743578/how-can-i-add-a-custome-icon-to-executables-created-with-ironpython-pyc-py)

    ipy.exe Tools\Scripts\pyc.py /main:C:\путь\к\isofc-client.ipy /standalone /embed /target:winexe
