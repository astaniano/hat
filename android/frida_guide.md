Frida works by injecting code into a running application and allowing you to interact with it in real-time. The code is injected into the process memory of the application, which means that it can be used to modify its behaviour without having to modify the actual source code. Frida provides a number of functions that allow you to interact with the application, including reading and writing memory, calling functions, and observing method calls

### Tools
Frida also comes with command line tools.
```
    Frida CLI # i.e. frida
    frida-ps
    frida-trace
    frida-discover
    frida-ls-devices
    frida-kill
```

### Before using frida:
We will be needing a rooted device or emulator as we need to inject script into the root directory of the device

In android studio emulator to enable root access: Pick an emulator system image that is NOT labelled "Google Play". (The label text and other UI details vary by Android Studio version.)
You might have to switch from the "Recommended" tab to the "x86 Images" or "Other Images" group to find one.

First off, download the latest `frida-server` for Android from our releases page: 
The Frida server is a small executable that runs on the target device and allows your computer to communicate with the device’s processes
```
https://github.com/frida/frida/releases
```
and uncompress it:
```bash
unxz frida-server.xz
```

Now, let's get it running on your device:
```bash
adb root # might be required
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"

# run frida server from desktop:
adb shell "/data/local/tmp/frida-server &"
# run server from inside the device:
adb shell
cd data/local/tmp
chmod 755 frida-server # (if was not done in the previous steps)
./frida-server
```
Some apps might be able to detect the frida-server location. Renaming the frida-server binary to a random name, or moving it to another location such as /dev may do the trick.

For the last step, make sure you start frida-server as root, i.e. if you are doing this on a rooted device, you might need to su and run it from that shell.

> If you get adbd `cannot run as root in production builds` after running `adb root`
> you need to prefix each shell command with `su -c`. 
> For example: 
```bash
adb shell "su -c chmod 755 /data/local/tmp/frida-server"
```

### Now locally install frida-tools with python3:
```bash
python3 -m venv frida_venv
source frida_venv/bin/activate
pip3 install frida-tools
pip3 install frida
frida --version

# Connect Frida to an iPad over USB and list running processes
frida-ps -U

# List running applications
frida-ps -Ua

# List installed applications
frida-ps -Uai

# Connect Frida to the specific device
frida-ps -D 0216027d1d6d3a03

#Get all the package name
frida-ps -U | grep -i <part_of_the_package_name> 
```

### To run the app on the phone:
```bash
#Hooking before starting the app
frida -U -l hookNative.js -f com.erev0s.jniapp
```
-U:
    This flag tells Frida to target a USB-connected device. Specifically, this is used when you want to interact with an app running on a mobile device that's connected via USB (rather than targeting a process on the local machine).

-f [package_name]:
    The -f flag is used to specify the package name of the application to target. This is typically the name of the app you want to hook or instrument (e.g., com.example.app).
    When used with Frida, this flag indicates that Frida should start the app, attach to it, and begin executing the script you provide.

-l myScript.js:
    The -l flag is used to load a JavaScript file (in this case, myScript.js). This JavaScript file contains the Frida script that will be injected into the target application.
    The script can include instructions to hook certain functions, modify behavior, dump data, or perform other types of analysis or manipulation.




### Additional:
### Tracing open() calls in Chrome
Alright, let’s have some fun. Fire up the Chrome app on your device and return to your desktop and run:

```bash
frida-trace -U -i open -N com.android.chrome
```
Uploading data...
open: Auto-generated handler …/linker/open.js
open: Auto-generated handler …/libc.so/open.js
Started tracing 2 functions. Press Ctrl+C to stop.

Now just play around with the Chrome app and you should start seeing open() calls flying in:
```
1392 ms	open()
1403 ms	open()
1420 ms	open()
```

You can now live-edit the aforementioned JavaScript files as you read man open, and start diving deeper and deeper into your Android apps.


