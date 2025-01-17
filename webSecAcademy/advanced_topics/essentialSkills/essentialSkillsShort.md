Basically you can scan individual requests with `Do active scan`

And we can also scan non-standard data structures with Right click > scan selected insertion point

Also note sometimes there might be a delay in the results of the scan. The delay in reporting the issue is due to the polling interval. By default, Burp polls the Burp Collaborator server for new interactions every minute

You can also use Intruder to define multiple insertion points. In the example above, you can define insertion points for 048857 and carlos, then right-click and select `Scan defined insertion points`. 

