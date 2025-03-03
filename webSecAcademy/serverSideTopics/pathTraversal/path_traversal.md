### File path traversal, simple case
This might load an image using the following HTML:
```
<img src="/loadImage?filename=218.png">
```
The image files are stored on disk in the location /var/www/images/. To return an image, the application appends the requested filename to this base directory and uses a filesystem API to read the contents of the file. In other words, the application reads from the following file path:
```
/var/www/images/218.png
```
We can change the src in img attribute to:
```
https://insecure-website.com/loadImage?filename=../../../etc/passwd
```
This causes the application to read from the following file path:
```
/var/www/images/../../../etc/passwd
```

On Windows, both ../ and ..\ are valid directory traversal sequences. The following is an example of an equivalent attack against a Windows-based server: 
```
https://insecure-website.com/loadImage?filename=..\..\..\windows\win.ini
```

## Common obstacles to exploiting path traversal vulnerabilities
If an application strips or blocks directory traversal sequences (`../..`) from the user-supplied filename, it might be possible to bypass the defense using a variety of techniques.

### traversal sequences blocked with absolute path bypass
You might be able to use an absolute path from the filesystem root, such as filename=/etc/passwd, to directly reference a file without using any traversal sequences.

### traversal sequences stripped non-recursively
You might be able to use nested traversal sequences, such as ....// or ....\/. These revert to simple traversal sequences when the inner sequence is stripped.
##### Lab: e.g.: ....//....//....//etc/passwd

### traversal sequences stripped with superfluous URL-decode
In some contexts, such as in a URL path or the filename parameter of a multipart/form-data request, web servers may strip any directory traversal sequences before passing your input to the application. You can sometimes bypass this kind of sanitization by URL encoding, or even double URL encoding, the `../` characters. This results in `%2e%2e%2f` and `%252e%252e%252f` respectively. 
TODO: Figure out: Various non-standard encodings, such as `..%c0%af` or `..%ef%bc%8f`, may also work.
##### Lab: e.g.: /image?filename=..%252f..%252f..%252fetc/passwd 

### File path traversal, validation of start of path
An application may require the user-supplied filename to start with the expected base folder, such as `/var/www/images`. In this case, it might be possible to include the required base folder followed by suitable traversal sequences. For example: `filename=/var/www/images/../../../etc/passwd`.
##### Lab: e.g.: /image?filename=/var/www/images/../../../etc/passwd

### File path traversal, validation of file extension with null byte bypass
An application may require the user-supplied filename to end with an expected file extension, such as .png. In this case, it might be possible to use a null byte to effectively terminate the file path before the required extension. For example: filename=../../../etc/passwd%00.png.


