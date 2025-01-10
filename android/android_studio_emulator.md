### Build emulator (copied from the following blog):
https://corsecure.blog/2023/08/08/build-an-android-emulator-with-android-studio/

Once you open the Device Manager, click Create Device, which will open a new window where you can begin customizing your device. The first option you will be asked to choose is the device hardware. This option will mostly only affect the look and feel of the emulator, but there is one detail that is pretty important for my purposes. This window should have a table showing some of the information about each of the hardware profiles, and one of the columns in this table will be labeled as Play Store. There should be a triangle-shaped logo in this column to denote the hardware profiles that have the Google Play Store enabled. It is important to choose a profile that does NOT have this enabled because the devices without the Play Store will be rooted by default. A rooted device is required for a lot of things that I want to do while testing Android apps, so having a rooted device out of the box just makes my job a little bit easier. The only downside is that you won’t be able to install production release apps from the Google Play Store, but in most cases when I am testing an application, I will be working with a non-production APK that I would sideload onto the device anyway

In order to launch your emulator from the command line, you must first find the Android SDK directory on your system. This can vary depending on your operating system. For my example, I am using a laptop running Ubuntu, and it is located at ~/Android/Sdk/. It should be in a similar location on MacOS, but for Windows, it will likely be located in the AppData directory. In a Windows machine that I tested it on, I found it in C:\Users\<my username>\App Data\Local\Android\Sdk\. Once you find that directory, you should see an emulator directory. Inside this directory run the following command:
```bash
# on macOS:
cd /Users/<user>/Library/Android/sdk/emulator

./emulator -list-avds
```

You should see the name of the emulator that you just created, and if you created multiple emulators, then you will see the names of all of the Android Studio emulator devices that are on your system. 

Once you have the name of the emulator that you want to run, then you can run the following command with your device name, which will launch your emulator:
```bash
./emulator -avd <AVD name>
```
For Windows, you would replace ./emulator with emulator.exe, but the rest of the commands would be the same.

### Emulator with burp (for Android 13 and below) (copied partly from the following link):
https://corsecure.blog/2023/08/17/using-burp-suite-with-an-android-emulator/

The first thing we need to do is export our certificate from Burp Suite in DER format. To do this, go to the Proxy settings in Burp Suite and click Import / Export CA Certificate. This will open a new window with multiple options for exporting or importing a certificate. In this window, select Export as Certificate in DER Format, and save that file with a .der file extension. For this example, I’m going to save mine as burpcert.der.

Prior to Android 7.0, we could just take this certificate, upload it to our Android emulator, and install it as a user certificate. If you are using a modern Android device though, we need to go through a few more steps to install this certificate as a system-level certificate.

To do this, we are going to need to have OpenSSL installed on our system. For my example, I am going to be running these commands on an Ubuntu system. If you are using MacOS, these commands should be the same. If you are using Windows, most of the commands should be pretty similar, but you will most likely have to do some extra work to get OpenSSL installed and configured on your system.

Run the following commands to properly format the certificate as a PEM file and rename the file:
```bash
openssl x509 -inform DER -in burpcert.der -out burpcert.pem

openssl x509 -inform PEM -subject_hash_old -in burpcert.pem | head -1
# output was 9a5ba575
```
Note: The second command will most likely return the hash 9a5ba575. Almost every time I have done this, it has resulted in that same hash, and I suspect that the only times I have gotten a different hash was due to a mistake on my part.

Once you have that hash from running the second command above, you now need to rename the PEM file using that hash.
```bash
mv burpcert.pem <hash>.0

mv burpcert.pem 9a5ba575.0
```

#### Installing the Certificate
Now that we have our certificate file properly formatted and correctly named, next we need to install the certificate onto our emulator as a system certificate. To do this, we’re going to have to remount the /system directory as writable. We can do this with adb, but we will have to run adb as root. Also, for an Android Studio emulator, we will need to launch that emulator as a writable system.

In order to remount the /system directory, we’re going to have to launch our emulator with the -writable-system flag. The command to launch the emulator with this option is below:
```bash
./emulator -avd <AVD name> -writable-system
```

Once your emulator launches, you can remount the file system with the following commands:
```bash
adb devices
adb root
adb remount
```

> Note: If the remount fails, check the Troubleshooting section at the bottom of the page. (below on the blog website, not here)

Once the file system is remounted, we need to upload the certificate to the emulator.  Do this with the following command:
```bash
adb push <certificate> /sdcard/
```

Next we need to drop into a shell and move the certificate to the proper directory and give it the proper permissions. To drop into a shell, simply run the command adb shell. After you are in the shell, run the following commands:
```bash
mv /sdcard/<certificate file> /system/etc/security/cacerts/
mv /sdcard/9a5ba575.0 /system/etc/security/cacerts/

chmod 644 /system/etc/security/cacerts/<certificate>
chmod 644 /system/etc/security/cacerts/9a5ba575.0
```

> Note: If moving the file to the /system directory fails, check the Troubleshooting section at the bottom of the page. (not at the bottom here, but at the bottom of the blog, the link is above)

After those commands run successfully, we just need to reboot our emulator by running `adb reboot`. Alternatively, if you are still in the adb shell, you can simply run `reboot`. Once the emulator reboots, we can verify that the certificate was properly installed by checking the `trusted credentials` under the security settings menu inside the emulator. If we see a certificate under System that is listed as `PortSwigger`, then we know that the certificate was installed correctly.



### Bypass ssl pinning with frida:
https://corsecure.blog/2023/08/24/bypassing-ssl-pinning-with-frida/

### Maybe checkout other posts here:
https://corsecure.blog/

