### 2.2 Parameter Manipulation
### 2.2.1 Price Manipulation
Applications normally send the price data to the payment pages, especially when
the payment module is not part of the web application and therefore does not have access to user
sessions or the database. It is also possible to find applications that send the price data upon selecting
an item to add it to the basket

try a negative number as a price

The e-commerce site’s “add to basket” mechanism contained a “price” parameter in a hidden field, but
the application ignored a manipulated price in the request and used the correct value instead.
However, it was found later that by adding a number of sale items (items with additional discounts) to
the basket, the application started using the price parameter within the request, and allowed price
manipulation and negative values (see the “Dynamic Prices, Prices with Tolerance, or Referral
Schemes” section for more information).

Sometimes, when the application is badly implemented, it is possible to change the price value on the
callback from the payment server (which goes through the user’s browser and not via the backend
APIs). In this case, the user can alter the price before going to the payment page, and after completing
the transaction the price in the callback URL will be changed to reflect its initial value. The user could
later ask for a refund and gain this money. It is quite rare

### 2.2.2 Currency Manipulation
Although an e-commerce website may not accept different currencies, payment applications normally
accept them, and they generally require the currency parameter to be specified in the initial request. If
a website does not validate the currency parameter upon completion of a transaction, a user can cheat
by depositing money in a currency which has a much lower value than the requested currency. The
following example shows a badly-implemented PayPal payment method that could be exploited:

A user makes a payment of £20 to a website, using the PayPal payment option. The request that the
website sent to the PayPal website was intercepted and the currency parameter was changed to “INR”
(Indian Rupee) from “GBP” (British Pound). After completing the transaction on the PayPal website with 20 Indian Rupees, the website authorised the transaction without checking the currency, and £20
was deposited in the user’s account while only £0.22 was withdrawn from the PayPal account

### 2.2.3 Quantity Manipulation
Websites calculate a final price based on the quantity of items purchased. Therefore, it may be possible
for this parameter to be manipulated to contain small or negative values, to affect the price on the final
payment page.

The website may remove items that have zero or negative values within the quantity parameters. In
this case, decimal values such as “0.01”, “0.51”, or “0.996” can be tested to see if they have any effects
on the final price. This method can be more dangerous when used on items which are not normally
manually reviewed

### 2.2.4 Shipping Address and Post Method Manipulation
Changing the shipping address and the posting method may change the cost of items. Therefore, it is
important to test this manipulation during the last stage of the payment process to check whether it
changes the cost. It is sometimes possible to change the shipping address after placing an order and
before receiving the invoice, by changing the user’s profile address, so this needs to be tested as well.
This can also be a TOCTOU issue – see the section above.
The tax value can also be based on the address. This should be tested to ensure that it is not easy for
an attacker to avoid required taxes, such as VAT or import fees, by manipulating the address in the
process.

### 2.2.5 Additional Costs Manipulation
Any additional parameter that can affect the final cost of a product, such as delivery at a specific time
or adding a gift wrap should also be tested, to ensure it is not possible to add them for free at any
stage of the payment process

### 2.2.6 Response Manipulation
Sometimes application payment processes, application license checks, or in-app asset purchases can
also be bypassed by manipulating the server’s response. This threat normally occurs when the
application does not verify the response of a third party and the response has not been
cryptographically signed
As an example, there are applications with a time-restricted trial version which do not cryptographically
validate the server’s response upon purchasing a license. As a result, it is possible to activate the
application without paying any money, by intercepting and manipulating its server’s response to a
license purchase request.
Other examples include mobile games which download user settings from a server after opening an
app. For vulnerable applications it can be possible to manipulate the server’s response to use non-
free or locked items without paying any money.

### 2.2.7 Repeating an Input Parameter Multiple Times
This is very rare, but repeating an input parameter within a request that goes to the application or to
the payment gateway may cause logical issues, especially when the application uses different
codebases or different technology to parse the inputs on the server side.
Different technologies may behave differently when they receive repetitive input parameters. This
becomes especially important when the application sends server-side requests to other applications
with different technologies, or when customised code to identify the inputs is in place.
For example, the “amount” parameter was repeated in the following URL:
```bash
/page.extension?amount=2&amount=3&amount[]=4
```
This has different meaning for code written in ASP, ASP.Net, or PHP, as shown below:
```bash
ASP -> amount = 2, 3
ASP.Net -> amount = 2,3
PHP (Apache) -> amount = Array
```
This test shows a classic example of HTTP parameter pollution [10]. However, repeating input
parameters is not only limited to normal GET or POST parameters, and could be used in other
scenarios such as repeating a number of XML tags and attributes in an XML request, or another JSON
object within the original JSON objects.

### 2.2.8 Omitting an Input Parameter or its Value
Similar to repeating input parameters, omitting parameters may also cause logical issues when the
application cannot find an input or sees a null character as the value.
The following cases can be tested for sensitive inputs to bypass certain protection mechanisms:
- Removing the value
- Replacing the value by a null character
- Removing the equals-sign character after the input parameter
- Removing the input parameter completely from the reques

### 2.2.9 Mass Assignment, Autobinding, or Object Injection
This occurs when an application accepts additional parameters when they are included in a request.
This can occur in a number of languages or frameworks such as Ruby on Rails, NodeJS, Spring MVC,
ASP NET MVC, and PHP.
This can be problematic for a financial application when cost-related data can be manipulated.
As an example, this was exploited on a real website in order to change the shipping address and the
“due to” date of an invoice to make it almost unpayable as it was set to date that was far in the future.

### 2.2.10 Monitor the Behaviour while Changing Parameters to Detect Logical Flaws
Just as when testing non-financial applications, all input parameters within the payment process should
be tested separately in order to detect logical flaws. In the example below, the payment process flow
could be changed by manipulating certain parameters:
In a web application, there was a parameter which was used to tell the server to use the 3D-Secure
mechanism, which could be manipulated to circumvent this checking process.
Sometimes web applications contain a parameter which shows the current page number or stage. A
user may be able to bypass certain stages or pages by manipulating this parameter in the next request
It is not normally recommended to change more than one parameter during a limited time frame of
testing; however, some logical flaws can be found only by changing more than one parameter at a
time. This is useful when an application detects parameter manipulation for parameters such as the
price field. Although it may not be feasible to test different combinations of all input parameters, it is
recommended to modify at least a couple of the interesting inputs at the same time. In order to
automate this test, the target field such as the price or the quantity parameter can be set to a specific
amount that is not normally allowed, and then other parameters can be changed one by one to detect
any possible bypass of current validation mechanisms when the application accepts the manipulated
items.
The following shows an example of this kind of vulnerability.
Suppose the server-side code is as follows:
```bash
1: Try
2: ' Delivery type should be an integer
3: deliveryType = Int(deliveryType)
4: ' Quantity should be an integer
5: quantity = Int(quantity)
6: Catch ex As Exception
7: ' Empty catch!
8: End Try
9: ' Continue ...
```
This code makes sure that the “deliveryType” variable contains an integer number, then does the same
thing for the “quantity” variable. Therefore, if decimal numbers are sent, they will be converted to
integer values to prevent a security issue in which a user may pay less by changing the “quantity”
parameter to a decimal value such as “0.1”. However, due to an empty Catch section in line 7, the
“quantity” parameter can still contain a decimal number such as “0.1” when the “deliveryType”
parameter contains a string such as “foobar”. In this case, the application jumps to the Catch section
due to an error in converting a string value to an integer in line 3, before converting the “quantity”
parameter to an integer.

### 2.3 Replay Attacks (Capture-Replay)
A replay attack occurs when all or part of a message between the client and the server are copied and
replayed later. The parameters can also be changed when no parameter manipulation prevention
technique such as message signature validation is present on the server side. Although a message
can be signed or encrypted to prevent parameter manipulation, this will not stop replay of a message
which was originally created by a trusted party.

### 2.3.1 Replaying the Call-back Request
TODO: most likely it is better to look into the pdf file

