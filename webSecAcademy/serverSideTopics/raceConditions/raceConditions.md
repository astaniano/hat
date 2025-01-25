### Limit overrun race conditions
There are many variations of this kind of attack, including: 
- Redeeming a gift card multiple times
- Rating a product multiple times
- Withdrawing or transferring cash in excess of your account balance
- Reusing a single CAPTCHA solution
- Bypassing an anti-brute-force rate limit

Limit overruns are a subtype of so-called "time-of-check to time-of-use" (TOCTOU) flaws

### APPRENTICE Lab: Limit overrun race conditions
There's an endpoint which applies a coupon code and therefore reduces the total price of the items in the cart
```bash
POST /cart/coupon HTTP/2
```

With race conditions we can apply it more than once.
Send to repeater > create a new tab group > on the right from the `Send` button click on arrow down and select `sending reqs in parallel`

This will send all those reqs in parallel and will reduce the price significantly. (you'll prolly need about 20 tabs)

### Detecting and exploiting limit overrun race conditions with Turbo Intruder
In addition to providing native support for the single-packet attack in Burp Repeater, we've also enhanced the Turbo Intruder extension to support this technique. You can download the latest version from the BApp Store.

Turbo Intruder requires some proficiency in Python, but is suited to more complex attacks, such as ones that require multiple retries, staggered request timing, or an extremely large number of requests. 

### PRACTITIONER Lab: Bypassing rate limits via race conditions
There's an account lock on the login endpoint

Infer that if you're quick enough, you're able to submit more than three login attempts before the account lock is triggered

This lab demonstrates that if there's an account lock on login functionality (e.g. not more than 3 attempts), we can still send more than 3 requests with race conditions

### Hidden multi-step sequences
Interesting but did not have time to document and skipped everything below up until multi-endpoint rc

### Multi-endpoint race conditions
### Aligning multi-endpoint race windows
When testing for multi-endpoint race conditions, you may encounter issues trying to line up the race windows for each request, even if you send them all at exactly the same time using the single-packet technique. 

This common problem is primarily caused by the following two factors:
- Delays introduced by network architecture - For example, there may be a delay whenever the front-end server establishes a new connection to the back-end. The protocol used can also have a major impact.
- Delays introduced by endpoint-specific processing - Different endpoints inherently vary in their processing times, sometimes significantly so, depending on what operations they trigger.

Fortunately, there are potential workarounds to both of these issues. 

### Connection warming
Back-end connection delays don't usually interfere with race condition attacks because they typically delay parallel requests equally, so the requests stay in sync.

It's essential to be able to distinguish these delays from those caused by endpoint-specific factors. One way to do this is by "warming" the connection with one or more inconsequential requests to see if this smoothes out the remaining processing times. In Burp Repeater, you can try adding a GET request for the homepage to the start of your tab group, then using the Send group in sequence (single connection) option.

If the first request still has a longer processing time, but the rest of the requests are now processed within a short window, you can ignore the apparent delay and continue testing as normal. 


