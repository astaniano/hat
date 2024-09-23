### Wrong assumptions that user will follow all the flow steps correctly
Flaws in the logic can allow attackers to circumvent these rules. For example, they might be able to complete a transaction without going through the intended purchase workflow. In other cases, broken or non-existent validation of user-supplied data might allow users to make arbitrary changes to transaction-critical values or submit nonsensical input. By passing unexpected values into server-side logic, an attacker can potentially induce the application to do something that it isn't supposed to.

Business logic vulnerabilities often arise because the design and development teams make flawed assumptions about how users will interact with the application. These bad assumptions can lead to inadequate validation of user input. For example, if the developers assume that users will pass data exclusively via a web browser, the application may rely entirely on weak client-side controls to validate input. These are easily bypassed by an attacker using an intercepting proxy.

Ultimately, this means that when an attacker deviates from the expected user behavior, the application fails to take appropriate steps to prevent this and, subsequently, fails to handle the situation safely.

Logic flaws are particularly common in overly complicated systems that even the development team themselves do not fully understand. To avoid logic flaws, developers need to understand the application as a whole. This includes being aware of how different functions can be combined in unexpected ways. Developers working on large code bases may not have an intimate understanding of how all areas of the application work. Someone working on one component could make flawed assumptions about how another component works and, as a result, inadvertently introduce serious logic flaws. If the developers do not explicitly document any assumptions that are being made, it is easy for these kinds of vulnerabilities to creep into an application.

Any unintended behavior can potentially lead to high-severity attacks if an attacker is able to manipulate the application in the right way. For this reason, quirky logic should ideally be fixed even if you can't work out how to exploit it yourself. There is always a risk that someone else will be able to.

You should also note that even though logic flaws may not allow an attacker to benefit directly, they could still allow a malicious party to damage the business in some way.

TODO: stopped here

#### Example 1: Email change does not require immediate confirmation
/admin can be accessed by a user with email @dontwannacry.com  
It's not possible to register users with that email  
However email change does not require immediate confirmation right away and we can change email to @dontwannacry.com and access /admin

#### Example 2: Insufficient workflow validation
Sometimes application relies on the order of the events e.g.:
If we want to buy a product we first need
POST /cart productId=1&redir=PRODUCT&quantity=1 (adds an item to the cart)
Then we need POST /cart/checkout csrf=...
Which redirects us to GET /cart/order-confirmation?order-confirmation=true

We can violate the sequence of the events by doing the following:
POST /cart productId=1&redir=PRODUCT&quantity=1 (adds an item to the cart)
Then we SKIP POST /cart/checkout csrf=... INSTEAD we fire the following
GET /cart/order-confirmation?order-confirmation=true
And we get an item for free

#### Example 3: Authentication bypass via flawed state machine
Let's say the usual flow is:
POST /login
GET /role-selector
POST /role-selector role=user

What we can do is:
POST /login
Then drop GET /role-selector in the burp intruder and as soon as it's droped our log in defaults to administrator and we can access /admin

#### Example 4: Online shop with a discount:
For example, consider an online shop that offers a 10% discount on orders over $1000. This could be vulnerable to abuse if the business logic fails to check whether the order was changed after the discount is applied. In this case, an attacker could simply add items to their cart until they hit the $1000 threshold, then remove the items they don't want before placing the order. They would then receive the discount on their order even though it no longer satisfies the intended criteria. 

### Think about missing `if` statements in endpoints
#### Remove more items from the cart than it currently has
Let's say there're 2 endpoints in an online website.  
One of them adds items to the cart and the second one removes items from the cart.  
Let's say the cart currently contains 1 item.  
Try to remove 2 items from the cart. Either by sending the same request twice or by specifying the bigger amount of items to remove in the req.body
This may result in the total cart price to be negative and therefore later you can add another item to it and buy that another item by a reduced price

#### Overloading integer (no `if` check for the total amount of items in the cart)
Let's say there's an endpoint that adds an item to a cart.  
The highest quantity is 99 per request.  
If there is no check for max amount of money in the cart we can overload an int: 
The price has exceeded the maximum value permitted for an integer in the back-end programming language (2,147,483,647). As a result, the value has looped back around to the minimum possible value (-2,147,483,648).  
It is possible that we are not allowed to buy items with a total negative sum in the cart but we can keep sending those requests until we get for example 1$ of total cart price and at the end we can add an expensive item and the total summ will be e.g. 30$ (above zero). But it would have been more expensive if we wanted to but that expensive item by its real price.


### Broken validation OR client-side only validation
#### Instead of validation input is truncated or certain chars are filtered out
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
And ofcourse we can now access `/admin` because our email is ending with `@dontwannacry`


### Know as much about the business logic (and business domain) as you can
####  e.g. 2 discount coupons that reset each others == infinite discount
If there are 2 different coupons that you can apply, there's a chance that it'll reset the first coupon in we'll be able to apply these 2 coupons one by one for ever

####  e.g. gift cards + coupons == infinite money
If there are both gift cards and coupons the following may be possible:
Put 10 gift cards for into the cart
in the cart apply discount coupon which reduces the price by e.g. 30%
i.e. the price for 10 coupons changes from 100$ to 70$
And buy those 10 gift cards for 70$
Then go to your account and apply those 10 gift cards : ))
You're +30$ of your initial money :))

### Authentication bypass via encryption oracle
The idea is that if there is an encrypted stay-logged-in cookie
and you can figure out how it's incrypted then you may encrypt a new stay-log-in cookie with the credentials of the admin
In the lab: if we send invalid email it sends us back this "notification" cookie which is an encrypted error msg that when decrypted is equal to:
"Invalid email address: <whatever your incorrect email was>"
Since we can now encrypt anything we want with the "Invalid email address: " prefix, we can later figure out how to encrypt stay-logged-in cookie

### Interesting:
You should pay particular attention to any situation where prices or other sensitive values are adjusted based on criteria determined by user actions. Try to understand what algorithms the application uses to make these adjustments and at what point these adjustments are made. This often involves manipulating the application so that it is in a state where the applied adjustments do not correspond to the original criteria intended by the developers. 


