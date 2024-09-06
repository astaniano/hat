### With rc you potentially can
- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of your account balance
- Reusing a single CAPTCHA solution
- Bypassing an anti-brute-force rate limit

### Limit overrun race conditions
- try to apply a discount more than once by sending parallel requests

### Bypassing rate limits via race conditions
- If there's a rate limit on login brute force, try to partially bypass it with RC

### Warm up request may sometimes help to adjust timing of RC

### Multistep RC between related or even unrelated endpoints
In practice, a single request may initiate an entire multi-step sequence behind the scenes, transitioning the application through multiple hidden states that it enters and then exits again before request processing is complete. We'll refer to these as "sub-states".

If you can identify one or more HTTP requests that cause an interaction with the same data, you can potentially abuse these sub-states to expose time-sensitive variations of the kinds of logic flaws that are common in multi-step workflows. This enables race condition exploits that go far beyond limit overruns. 

#### Lab example:
There are 2 endpoints:
1) `POST /cart` adds items to the cart 
2) `POST /cart/checkout` first checks whether customer has enough money and then checks out the items
There might be a race window: Let's say the second endpoint checked that a cutomer has enough money but hasn't checkout out the items yet. In between those 2 steps we can try to add another very expensive item to the cart and it will be checked out without money taken out of the customer's wallet. 

### Single-endpoint race conditions

### Partial construction race conditions

### Time-sensitive attacks
if reset password token is generated based on a current timestamp then we can try to reset password for 2 users simultaniously and use the same token for a different user. 
Since token is created based on the timestamp - the token for password reset of another user may be the same
