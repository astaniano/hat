// https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/ProxyHttpRequestResponse.html
// https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/requests/HttpRequest.html

var url = requestResponse.finalRequest().url();

String[] exclude = {
    "cdn.optimizely.com",
    "content-autofill.googleapis.com",
};

for (String exludedUrl : exclude) {
    if (url.contains(exludedUrl)) {
        return false;
    }
}

return true;
