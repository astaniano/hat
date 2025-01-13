Successful exploitation of prototype pollution requires the following key components:
- A prototype pollution source - This is any input that enables you to poison prototype objects with arbitrary properties.
- A sink - In other words, a JavaScript function or DOM element that enables arbitrary code execution.
- An exploitable gadget - This is any property that is passed into a sink without proper filtering or sanitization.

### Prototype pollution sources
A prototype pollution source is any user-controllable input that enables you to add arbitrary properties to prototype objects. The most common sources are as follows:
    The URL via either the query or fragment string (hash)
    JSON-based input
    Web messages

### Prototype pollution via the URL


