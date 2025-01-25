TODO: race conditions

## 2.2 Parameter Manipulation
### 2.2.1 Price Manipulation
Applications normally send the price data to the payment pages, especially when
the payment module is not part of the web application and therefore does not have access to user
sessions or the database. It is also possible to find applications that send the price data upon selecting
an item to add it to the basket

try a negative number as a price

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

### 2.2.5 Additional Costs Manipulation
Any additional parameter that can affect the final cost of a product, such as delivery at a specific time
or adding a gift wrap should also be tested, to ensure it is not possible to add them for free at any
stage of the payment process

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

### 2.4 Rounding Errors
### 2.4.1 Currency Rounding Issues


