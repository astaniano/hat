// https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/proxy/ProxyHttpRequestResponse.html
// https://portswigger.github.io/burp-extensions-montoya-api/javadoc/burp/api/montoya/http/message/requests/HttpRequest.html

var url = requestResponse.finalRequest().url();

String[] exclude = {
    "https://",
};

for (String exludedUrl : exclude) {
    if (url.startsWith(exludedUrl)) {
        return false;
    }
}

return true;
