# Apache Access
## References 
https://tomcat.apache.org/tomcat-8.5-doc/config/valve.html#Access_Logging
https://www.sentinelone.com/blog/detailed-introduction-apache-access-log/
https://www.sumologic.com/blog/apache-access-log/

Piped Log Process
- https://httpd.apache.org/docs/2.4/logs.html#piped

Custom Log Directive
- https://httpd.apache.org/docs/2.4/mod/mod_log_config.html#customlog

## Notable
- Apache access log is a source of information about who is accessing your website and how
- Location of log is dependent on the system which is running Apache HTTP Server
- Default Linux Log Location
	- /var/log/apache2/access.log
- Alternate Locations
	- /var/log/httpd/access.log
	- /var/log/httpd/access_log

## Log Fields & Examples
Example Common Log Format
~~~
127.0.0.1 - Scott [10/Dec/2019:13:55:36 -0700] "GET /server-status HTTP/1.1" 200 2326
~~~

The fields in the above sample record represent the following
127.0.0.1 
- Ipaddress of the client that made the request

The hyphen defining the second field in the log file is the identity of the client. 
- This field is often returned as a hyphen and recommends that this particular field not be relied upon except in the case of a controlled internal network.
- https://httpd.apache.org/docs/2.4/logs.html#accesslog

Scott
- userid of the person requesting the resource

10/Dec/2019:13:55:36 -0700 
- date and time of the request

“GET /server-status HTTP/1.1"
- request type and resource being requested

200
- HTTP response status code

2326
- size of the object returned to the client
