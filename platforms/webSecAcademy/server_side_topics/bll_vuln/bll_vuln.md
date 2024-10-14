Flaws in the logic can allow attackers to circumvent these rules. For example, they might be able to complete a transaction without going through the intended purchase workflow. In other cases, broken or non-existent validation of user-supplied data might allow users to make arbitrary changes to transaction-critical values or submit nonsensical input. By passing unexpected values into server-side logic, an attacker can potentially induce the application to do something that it isn't supposed to.

Business logic vulnerabilities often arise because the design and development teams make flawed assumptions about how users will interact with the application. These bad assumptions can lead to inadequate validation of user input. For example, if the developers assume that users will pass data exclusively via a web browser, the application may rely entirely on weak client-side controls to validate input. These are easily bypassed by an attacker using an intercepting proxy.

Ultimately, this means that when an attacker deviates from the expected user behavior, the application fails to take appropriate steps to prevent this and, subsequently, fails to handle the situation safely.

Logic flaws are particularly common in overly complicated systems that even the development team themselves do not fully understand. To avoid logic flaws, developers need to understand the application as a whole. This includes being aware of how different functions can be combined in unexpected ways. Developers working on large code bases may not have an intimate understanding of how all areas of the application work. Someone working on one component could make flawed assumptions about how another component works and, as a result, inadvertently introduce serious logic flaws. If the developers do not explicitly document any assumptions that are being made, it is easy for these kinds of vulnerabilities to creep into an application.

Any unintended behavior can potentially lead to high-severity attacks if an attacker is able to manipulate the application in the right way. For this reason, quirky logic should ideally be fixed even if you can't work out how to exploit it yourself. There is always a risk that someone else will be able to.

You should also note that even though logic flaws may not allow an attacker to benefit directly, they could still allow a malicious party to damage the business in some way.

### Lab: Excessive trust in client-side controls
Client side validation exists. But server side validation does not.

### Lab: 2FA broken logic
Duplicated in authentication vulnerabilities

### Failing to handle unconventional input
Try input in ranges that legitimate users are unlikely to ever enter. This includes exceptionally high or exceptionally low numeric inputs and abnormally long strings for text-based fields. You can even try unexpected data types. By observing the application's response, you should try and answer the following questions:
- Are there any limits that are imposed on the data?
- What happens when you reach those limits?
- Is any transformation or normalization being performed on your input?
This may expose weak input validation that allows you to manipulate the application in unusual ways. Keep in mind that if you find one form on the target website that fails to safely handle unconventional input, it's likely that other forms will have the same issues. 

### Think about missing `if` statements in endpoints
Let's say there're 2 endpoints in an online website.  
One of them adds items to the cart and the second one removes items from the cart.  
Let's say the cart currently contains 1 item.  
Try to remove 2 items from the cart. Either by sending the same request twice or by specifying the bigger amount of items to remove in the req.body
This may result in the total cart price to be negative and therefore later you can add another item to it and buy that another item by a reduced price

### Lab: High-level logic vulnerability
When adding a new item to a cart the request contains `quantity` parameter.
It turns out this quantity parameter can be changed to a lower number or to 0 or even to a negative number.
To solve the lab ddd the leather jacket to your cart as normal. Add a suitable negative quantity of the another item to reduce the total price to less than your remaining store credit. 

### Lab: Low-level logic flaw
Let's say there's an endpoint that adds an item to a cart.  
The highest quantity of items is 99 per request.  
If there is no check for max amount of money in the cart we can overload an int: 
The price has exceeded the maximum value permitted for an integer in the back-end programming language (2,147,483,647). As a result, the value has looped back around to the minimum possible value (-2,147,483,648).  
It is possible that we are not allowed to buy items with a total negative sum in the cart but we can keep sending those requests until we get for example 1$ of total cart price and at the end we can add an expensive item and the total sum will be e.g. 30$ (above zero). But it would have been more expensive if we wanted to buy that expensive item by its real price.

### Lab: Inconsistent handling of exceptional input
Summary: Instead of validating input it truncates it or it filters out certain chars
Let's say there's `/admin` endpoint but only registered users with `@dontwannacry.com` email can access it.  
If user email is truncated during a new user registration then we can try to create a new user with `@dontwannacry.com` email.  
Let's say we have an email: `attacker@exploit-0a3f003f039a744580e27023010a0015.exploit-server.net`  
And during registration in the email input we can specify:
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@dontwannacry.com.exploit-0a1b003c030d7ced81444731015d0049.exploit-server.net
```
Registration email will be sent to `attacker@exploit-0a3f003f039a744580e27023010a0015.exploit-server.net` but when the registration is complete and we login into our newly created account we'll see that our user's new email is truncated to 
```
aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb@dontwannacry.com
```
And of course we can now access `/admin` because our email is ending with `@dontwannacry`


## Making flawed assumptions about user behavior
### Trusted users won't always remain trustworthy
Applications may appear to be secure because they implement seemingly robust measures to enforce the business rules. Unfortunately, some applications make the mistake of assuming that, having passed these strict controls initially, the user and their data can be trusted indefinitely. This can result in relatively lax enforcement of the same controls from that point on.

If business rules and security measures are not applied consistently throughout the application, this can lead to potentially dangerous loopholes that may be exploited by an attacker. 

### Lab: Inconsistent security controls
Summary: Email change does not require immediate confirmation
Error msg on `/admin` indicates that `/admin` can only be accessed by users with email @dontwannacry.com  
It's not possible to register users with that email  
However when logged in users try to change their email, email change process does not require immediate confirmation right away and we can change email to @dontwannacry.com and access /admin

### Users won't always supply mandatory input
One misconception is that users will always supply values for mandatory input fields.

When probing for logic flaws, you should try removing each parameter in turn and observing what effect this has on the response. You should make sure to:
- Only remove one parameter at a time to ensure all relevant code paths are reached.
- Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
- Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow.
 
This applies to both URL and POST parameters, but don't forget to check the cookies too. This simple process can reveal some bizarre application behavior that may be exploitable. 

### Lab: Weak isolation on dual-use endpoint
There's a change password endpoint: POST /my-account/change-password
Notice that if you remove the current-password parameter entirely, you are able to successfully change your password without providing your current one. 
Observe that the user whose password is changed is determined by the username parameter. Set username=administrator and send the request again.
Log out and notice that you can now successfully log in as the administrator using the password you just set.

### Lab: Password reset broken logic
So if users want to reset their password they first click reset password  
Then a new message is sent to their email, containing the link to a password reset page.
On the password reset page users submit the following req:
```
POST /forgot-password?temp-forgot-password-token

username=wiener
```
When we play around with the req above we notice that password reset functionality still works even if you delete the value of the temp-forgot-password-token parameter
What's even worse is that we can change the value of `username` in the req.body, and change it to the username of another user and therefore we're able to change passwords of other users.

### Users won't always follow the intended sequence
Many transactions rely on predefined workflows consisting of a sequence of steps. The web interface will typically guide users through this process, taking them to the next step of the workflow each time they complete the current one. However, attackers won't necessarily adhere to this intended sequence. Failing to account for this possibility can lead to dangerous flaws that may be relatively simple to exploit

### Lab: 2FA simple bypass
Let's say you have valid login and password.
After entering them you're redirected to 2FA page. 
Try navigating directly to `/my-account` page without entering MFA code

### Interesting:
You should try to submit requests in an unintended sequence. For example, you might skip certain steps, access a single step more than once, return to earlier steps, and so on. Take note of how different steps are accessed. Although you often just submit a GET or POST request to a specific URL, sometimes you can access steps by submitting different sets of parameters to the same URL. As with all logic flaws, try to identify what assumptions the developers have made and where the attack surface lies. You can then look for ways of violating these assumptions. 

Note that this kind of testing will often cause exceptions because expected variables have null or uninitialized values. Arriving at a location in a partly defined or inconsistent state is also likely to cause the application to complain. In this case, be sure to pay close attention to any error messages or debug information that you encounter. These can be a valuable source of information disclosure, which can help you fine-tune your attack and understand key details about the back-end behavior. 

### Lab: Insufficient workflow validation
Sometimes application relies on the order of the events e.g.:
If we want to buy a product we first need
```
POST /cart productId=1&redir=PRODUCT&quantity=1 (adds an item to the cart)
```
Then we need 
```
POST /cart/checkout csrf=...
```
Which redirects us to 
```
GET /cart/order-confirmation?order-confirmation=true
```
We can violate the sequence of the events by doing the following:
```
POST /cart productId=1&redir=PRODUCT&quantity=1 (adds an item to the cart)
```
Then we skip 
```
POST /cart/checkout csrf=... 
```
instead we fire the following
```
GET /cart/order-confirmation?order-confirmation=true
```
And we get an item for free

### Lab: Authentication bypass via flawed state machine
Let's say the usual flow is:
```
POST /login
GET /role-selector
POST /role-selector role=user
```
What we can do is:
POST /login  
Then drop GET /role-selector in the burp intruder and as soon as it's dropped, our log in defaults to administrator and we can access /admin  

### Domain-specific flaws
Consider an online shop that offers a 10% discount on orders over $1000. This could be vulnerable to abuse if the business logic fails to check whether the order was changed after the discount is applied. In this case, an attacker could simply add items to their cart until they hit the $1000 threshold, then remove the items they don't want before placing the order. They would then receive the discount on their order even though it no longer satisfies the intended criteria. 

You should pay particular attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions. Try to understand what algorithms the application uses to make these adjustments and at what point these adjustments are made. This often involves manipulating the application so that it is in a state where the applied adjustments do not correspond to the original criteria intended by the developers. 

To identify these vulnerabilities, you need to think carefully about what objectives an attacker might have and try to find different ways of achieving this using the provided functionality. This may require a certain level of domain-specific knowledge in order to understand what might be advantageous in a given context. To use a simple example, you need to understand social media to understand the benefits of forcing a large number of users to follow you. 

### Lab: Flawed enforcement of business rules
If there are 2 different coupons that you can apply, there's a chance that applying second coupon resets the first coupon  
Try applying the coupons more than once. Notice that if you enter the same code twice in a row, it is rejected because the coupon has already been applied. However, if you alternate between the two codes, you can bypass this control. 
Therefore we're able to apply these 2 coupons one by one for ever (they will reset each other for ever)

### Lab: Infinite money logic flaw
If there are both gift cards and coupons the following may be possible:
Put 10 gift cards into the cart
in the cart apply discount coupon which reduces the price by e.g. 30%
i.e. the price for 10 coupons changes from 100$ to 70$
And buy those 10 gift cards for 70$
Then go to your account and redeem those 10 gift cards : ))
You're +30$ of your initial money :))

### Lab: Authentication bypass via encryption oracle
The idea is that if there is an encrypted stay-logged-in cookie
and you can figure out how it is encrypted then you may encrypt a new stay-log-in cookie with the credentials of the admin
In the lab: if we send invalid email it sends us back this "notification" cookie which is an encrypted error msg that when decrypted is equal to:
`Invalid email address: <whatever your incorrect email was>`
Since we can now encrypt anything we want with the "Invalid email address: " prefix, we can later figure out how to encrypt stay-logged-in cookie


