### Wrong assumptions that user will follow all the flow steps correctly
- In general think about assumptions that developers make about users and try to get around them
- Don't go through all the flow sequentially or:
  - skip certain steps, access a single step more than once, return to earlier steps
- Validation and `if`s may only be present in the beginning of the flow but not in subsequent steps
- Example 1: Email change does not require immediate confirmation
- The presence or absence of a particular parameter may determine which code is executed  

### Broken validation OR client-side only validation
- Pay for a product with a negative value or with other nonsensical input
- Instead of validation input is truncated or certain chars are filtered out

### Probing for errors (url params, queries and req.body, cookies)
- Try deleting the name of the parameter as well as the value. The server will typically handle both cases differently.
- Follow multi-stage processes through to completion. Sometimes tampering with a parameter in one step will have an effect on another step further along in the workflow. 
- Example: remove current pass param from from reset password endpoint and it may update the password to a new one without checking for current pass
