# s3_request.py

### Copyright (C) 2021 by Robert &lt;modrobert@gmail.com&gt;
### Software licensed under Zero Clause BSD.

---

### Description

Simple AWS S3 request command-line tool written in Python which supports both v2 and v4 signing during authentication. The reason to support v2 signing which is obsolete is to make it compatible with Spectra BlackPearl Converged Storage System. Should work fine with Python 2.7.x and 3+.

---

### Usage

<pre>
$ ./s3_request.py -h
usage: s3_request.py [-h] (-a ACCESS | -t TOKEN)
                     [-m {GET,PUT,POST,HEAD,DELETE}] [-c CONTENT_TYPE]
                     [-si {v2,v4}] [-r REGION] [-se SERVICE] -u URL [-cv]
                     [-of OUTPUT_FILE | -pr | -js] [-q | -v]
                     [-pf PAYLOAD_FILE | -ps PAYLOAD_STRING]

Simple AWS S3 request tool.

optional arguments:
  -h, --help            show this help message and exit
  -a ACCESS, --access ACCESS
                        aws access key &lt;id:secret&gt;, eg: myid:mysecret
  -t TOKEN, --token TOKEN
                        aws access token
  -m {GET,PUT,POST,HEAD,DELETE}, --method {GET,PUT,POST,HEAD,DELETE}
                        request method (default: GET)
  -c CONTENT_TYPE, --content_type CONTENT_TYPE
                        header content-type, eg: application/octet-stream
  -si {v2,v4}, --signing {v2,v4}
                        aws signing method (default: v4)
  -r REGION, --region REGION
                        aws region for v4 signing (default: ap-southeast-1)
  -se SERVICE, --service SERVICE
                        aws service for v4 signing (default: s3)
  -u URL, --url URL     server url, eg:
                        https://example.amazonaws.com:8080/bucket/foo
  -cv, --cert_verify    verify https cert
  -of OUTPUT_FILE, --output_file OUTPUT_FILE
                        write response content to file
  -pr, --pretty_print   pretty print xml response content
  -js, --json_print     pretty print json response content
  -q, --quiet           no output except errors, exit result is set to 4 for
                        http response code 400 and above
  -v, --verbose         show more info
  -pf PAYLOAD_FILE, --payload_file PAYLOAD_FILE
                        payload from file
  -ps PAYLOAD_STRING, --payload_string PAYLOAD_STRING
                        payload in string
</pre>

---

### Examples
 

##### PUT object in bucket (copy file to bucket):
<pre>
s3_request.py -a access_key_id:secret_access_key -r "ap-southeast-1" -si v4 -m PUT -u "https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md" -v -pf README.md -c "application/octet-stream"


--[AUTH]---------------------------------------------&gt;
HTTPS cert verification: False
AWS S3 signing: v4
Access Key ID: access_key_id
Secret Access Key: secret_access_key

--[REQUEST]------------------------------------------&gt;
Request method: PUT
Request URL: https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md
Request headers: {"Content-Type": "application/octet-stream", "x-amz-content-sha256": "000426f28601c7a9685422a692354e6ca9bd2a19aa2d198785c69cf6beb3a4d1", "x-amz-date": "20200416T115044Z", "Authorization": "AWS4-HMAC-SHA256 Credential=access_key_id/20200416/ap-southeast-1/s3/aws4_request, SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date, Signature=d25fde29b0ba17b09323647abfb81b0472e661d83db26d38ebe940b4f047eb0c"}

--[RESPONSE]-----------------------------------------&gt;
Response code: 200
Response headers: {'x-amz-id-2': 'Jtf99RhxLhvCTuee75wOC31cxZrj1JPWy9St7TTzMsjnogjITtxCiKDYf4jWE1B2EE1Eb2WYwDQ=', 'x-amz-request-id': 'A00C634C0F718F26', 'Date': 'Thu, 16 Apr 2020 11:50:45 GMT', 'ETag': '"65ffc5f976a0697828cde2d5fcd4a09c"', 'Content-Length': '0', 'Server': 'AmazonS3'}
</pre>
 

##### GET list of objects in bucket (list files in bucket):
<pre>
s3_request.py -a access_key_id:secret_access_key -r "ap-southeast-1" -si v4 -m GET -u "https://rvesterlund.s3.ap-southeast-1.amazonaws.com/?" -v -pr

--[AUTH]---------------------------------------------&gt;
HTTPS cert verification: False
AWS S3 signing: v4
Access Key ID: access_key_id
Secret Access Key: secret_access_key

--[REQUEST]------------------------------------------&gt;
Request method: GET
Request URL: https://rvesterlund.s3.ap-southeast-1.amazonaws.com/
Request headers: {"x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date": "20200416T115047Z", "Authorization": "AWS4-HMAC-SHA256 Credential=access_key_id/20200416/ap-southeast-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=fafff689437853872b79087e8ee7b024c69b6ea14b2795f1d821711f5c0e5cf7"}

--[RESPONSE]-----------------------------------------&gt;
Response code: 200
Response headers: {'x-amz-id-2': 'hEe+7KneI0LmY8/JwV+1Tt+Cye1dK7J/uzxlnXcZ9YFZKncMNZ3WOGWIuH4R9DOSTkbnS2TKDAE=', 'x-amz-request-id': '167A3FD1C99FF5AC', 'Date': 'Thu, 16 Apr 2020 11:50:49 GMT', 'x-amz-bucket-region': 'ap-southeast-1', 'Content-Type': 'application/xml', 'Transfer-Encoding': 'chunked', 'Server': 'AmazonS3'}

Response content (pretty):
&lt;?xml version="1.0" ?&gt;
&lt;ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"&gt;
	&lt;Name&gt;rvesterlund&lt;/Name&gt;
	&lt;Prefix/&gt;
	&lt;Marker/&gt;
	&lt;MaxKeys&gt;1000&lt;/MaxKeys&gt;
	&lt;IsTruncated&gt;false&lt;/IsTruncated&gt;
	&lt;Contents&gt;
		&lt;Key&gt;README.md&lt;/Key&gt;
		&lt;LastModified&gt;2020-04-16T11:50:45.000Z&lt;/LastModified&gt;
		&lt;ETag&gt;&quot;65ffc5f976a0697828cde2d5fcd4a09c&quot;&lt;/ETag&gt;
		&lt;Size&gt;2439&lt;/Size&gt;
		&lt;Owner&gt;
			&lt;ID&gt;0c395d7960ddf7ecb019ed4046ed22782124fb03dc2f1e7ba9bf34f7d1d89733&lt;/ID&gt;
			&lt;DisplayName&gt;crh&lt;/DisplayName&gt;
		&lt;/Owner&gt;
		&lt;StorageClass&gt;STANDARD&lt;/StorageClass&gt;
	&lt;/Contents&gt;
&lt;/ListBucketResult&gt;
</pre>
 

##### GET object from bucket and save to file (copy file from bucket):
<pre>
s3_request.py -a access_key_id:secret_access_key -r "ap-southeast-1" -si v4 -m GET -u "https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md" -v -of /tmp/test.txt

--[AUTH]---------------------------------------------&gt;
HTTPS cert verification: False
AWS S3 signing: v4
Access Key ID: access_key_id
Secret Access Key: secret_access_key

--[REQUEST]------------------------------------------&gt;
Request method: GET
Request URL: https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md
Request headers: {"x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date": "20200416T124238Z", "Authorization": "AWS4-HMAC-SHA256 Credential=access_key_id/20200416/ap-southeast-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=0d9f6be7cd8eb5e5efebaf6841c4be6d25e5befe5573f2f0fe9c4515bca25fdf"}

--[RESPONSE]-----------------------------------------&gt;
Response code: 200
Response headers: {'Content-Length': '2439', 'x-amz-id-2': 'jHLnFxwqhhbKb0yBH1qT0i68NKFakYYipU41THj28EomL80Oqi3pUspPN5OcpNEPElN1YgDC83k=', 'Accept-Ranges': 'bytes', 'Server': 'AmazonS3', 'Last-Modified': 'Thu, 16 Apr 2020 11:50:45 GMT', 'ETag': '"65ffc5f976a0697828cde2d5fcd4a09c"', 'x-amz-request-id': 'BB7331D05966D2FC', 'Date': 'Thu, 16 Apr 2020 12:42:39 GMT', 'Content-Type': 'application/octet-stream'}

Writing response content to file: /tmp/test.txt
Done.
</pre>
 

##### DELETE object in bucket (delete file):
<pre>
s3_request.py -a access_key_id:secret_access_key -r "ap-southeast-1" -si v4 -m DELETE -u "https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md" -v

--[AUTH]---------------------------------------------&gt;
HTTPS cert verification: False
AWS S3 signing: v4
Access Key ID: access_key_id
Secret Access Key: secret_access_key

--[REQUEST]------------------------------------------&gt;
Request method: DELETE
Request URL: https://rvesterlund.s3.ap-southeast-1.amazonaws.com/README.md
Request headers: {"x-amz-content-sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "x-amz-date": "20200416T115028Z", "Authorization": "AWS4-HMAC-SHA256 Credential=access_key_id/20200416/ap-southeast-1/s3/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=21d578f12a9030f4bceb877026a3d058ae91c59e94d78dbb8a9526cafd09dc60"}

--[RESPONSE]-----------------------------------------&gt;
Response code: 204
Response headers: {'x-amz-id-2': 'f5k90Krq+7xLbNtM8ajKLZbZe5vXRGL6KdBmnVN0E8Xg9fjs0xv+r+oWrE2t9ZdC/AnePbw0o4c=', 'Date': 'Thu, 16 Apr 2020 11:50:29 GMT', 'x-amz-request-id': '67BFEFAC248D517A', 'Server': 'AmazonS3'}
</pre>
