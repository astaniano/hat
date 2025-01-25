### Multistep RC between related or even unrelated endpoints
In practice, a single request may initiate an entire multi-step sequence behind the scenes, transitioning the application through multiple hidden states that it enters and then exits again before request processing is complete. We'll refer to these as "sub-states".

If you can identify one or more HTTP requests that cause an interaction with the same data, you can potentially abuse these sub-states to expose time-sensitive variations of the kinds of logic flaws that are common in multi-step workflows. This enables race condition exploits that go far beyond limit overruns. 

#### Lab example:
There are 2 endpoints:
1) `POST /cart` adds items to the cart 
2) `POST /cart/checkout` first checks whether customer has enough money and then checks out the items
There might be a race window: Let's say the second endpoint checked that a cutomer has enough money but hasn't checkout out the items yet. In between those 2 steps we can try to add another very expensive item to the cart and it will be checked out without money taken out of the customer's wallet. 

### Time-sensitive attacks
if reset password token is generated based on a current timestamp then we can try to reset password for 2 users simultaniously and use the same token for a different user. 
Since token is created based on the timestamp - the token for password reset of another user may be the same

### Single-endpoint race conditions
Let's say there's a reset email functionality
Consider that there may be a race window between when the website:
    Kicks off a task that eventually sends an email to the provided address.
    Retrieves data from the database and uses this to render the email template.
I.e. email that resets email may be sent to your own email but it will update email to email of another user

### Interesting
Some frameworks attempt to prevent accidental data corruption by using some form of request locking. For example, PHP's native session handler module only processes one request per session at a time.

It's extremely important to spot this kind of behavior as it can otherwise mask trivially exploitable vulnerabilities. If you notice that all of your requests are being processed sequentially, try sending each of them using a different session token. 

### Partial construction race conditions
Let's say there are 2 endpoints in the registration flow:
POST /register
POST /confirm?token[]=

POST /register endpoint may do the following:
1. create (insert) user into the db
2. generate random registration confirmation token
3. update user record (update registration token field with the newly created token)

The idea is to catch this race window when user is created but reg_token field is equal to null)

In php we can make something like:
http://localhost/info.php?param[]=
And param[]= will be equal to null
So in the POST /confirm endpoint it'll get a val from user.reg_token field which will be NULL if we got into that race window successfully and null will be equal to null so the registration will be confirmed

