#!/usr/bin/env python
#
# s3_request.py - Simple AWS S3 request tool.
# Copyright (C) 2021 by Robert <modrobert@gmail.com>
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES WITH
# REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT,
# INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR
# OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
# PERFORMANCE OF THIS SOFTWARE.
#
# Supports Python 2.7.x and 3+.
#

"""
Simple AWS S3 request tool.
"""

import argparse
import base64
import datetime
import hashlib
import hmac
import json
import os
import requests
import sys
import urllib3
import xml.dom.minidom

from collections import OrderedDict

try:
    # Python 2.
    from urlparse import urlparse
except ImportError:
    # Python 3.
    from urllib.parse import urlparse

MAX_PRINT_SIZE = 1000000


def sign_v2(key, msg):
    """
    AWS version 2 signing by sha1 hashing and base64 encode.
    """
    return base64.b64encode(hmac.new(key, msg.encode("utf-8"), hashlib.sha1).digest())


def sign_v4(key, msg):
    """
    AWS version 4 signing by sha256 hashing.
    """
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()


def get_sig_key_v4(key, date_stamp, region_name, service_name):
    """
    AWS version 4 signing of the signature.
    """
    k_date = sign_v4(("AWS4" + key).encode("utf-8"), date_stamp)
    k_region = sign_v4(k_date, region_name)
    k_service = sign_v4(k_region, service_name)
    k_signing = sign_v4(k_service, "aws4_request")
    return k_signing


def build_request_v2(access_key, secret_key, args):
    """
    Build AWS request for signing version 2.
    """
    up = urlparse(args.url)
    request_path = up.path
    if request_path == "":
        request_path = "/"
    endpoint = up.scheme + "://" + up.netloc + request_path
    host = up.netloc

    t = datetime.datetime.utcnow()
    date = t.strftime("%a, %d %b %Y %H:%M:%S GMT")

    if args.method == "POST" and args.content_type != "":
        string_to_sign = (
            args.method
            + "\n"
            + "\n"
            + args.content_type
            + "\n"
            + date
            + "\n"
            + request_path
        )
    elif args.method == "PUT" and args.content_type != "":
        string_to_sign = (
            args.method
            + "\n"
            + "\n"
            + args.content_type
            + "\n"
            + date
            + "\n"
            + request_path
        )
    else:
        string_to_sign = args.method + "\n" + "\n" + "\n" + date + "\n" + request_path

    signature = sign_v2(secret_key, string_to_sign)
    auth_header = "AWS" + " " + access_key + ":" + signature

    if args.method == "POST" and args.content_type != "":
        headers = OrderedDict(
            [
                ("Content-Type", args.content_type),
                ("Date", date),
                ("Authorization", auth_header),
                ("User-Agent", "python-requests/2.2"),
                ("Host", host),
            ]
        )
    elif args.method == "PUT" and args.content_type != "":
        headers = OrderedDict(
            [
                ("Content-Type", args.content_type),
                ("Date", date),
                ("Authorization", auth_header),
                ("User-Agent", "python-requests/2.2"),
                ("Host", host),
            ]
        )
    else:
        headers = OrderedDict(
            [
                ("Date", date),
                ("Authorization", auth_header),
                ("User-Agent", "python-requests/2.2"),
                ("Host", host),
            ]
        )

    if up.query == "":
        request_url = endpoint
    else:
        request_url = endpoint + "?" + up.query

    return request_url, headers


def build_request_v4(access_key, secret_key, args, payload):
    """
    Build AWS request for signing version 4.
    """
    up = urlparse(args.url)
    canonical_uri = up.path
    if canonical_uri == "":
        canonical_uri = "/"

    endpoint = up.scheme + "://" + up.netloc + canonical_uri

    host = up.netloc

    if args.method == "POST":
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    elif args.method == "PUT":
        payload_hash = hashlib.sha256(payload.encode("utf-8")).hexdigest()
    else:
        payload_hash = hashlib.sha256(("").encode("utf-8")).hexdigest()

    t = datetime.datetime.utcnow()
    amzdate = t.strftime("%Y%m%dT%H%M%SZ")
    datestamp = t.strftime("%Y%m%d")

    if args.method == "POST" and args.content_type != "":
        canonical_headers = (
            "content-type:"
            + args.content_type
            + "\n"
            + "host:"
            + host
            + "\n"
            + "x-amz-content-sha256:"
            + payload_hash
            + "\n"
            + "x-amz-date:"
            + amzdate
            + "\n"
        )
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"
    elif args.method == "PUT" and args.content_type != "":
        canonical_headers = (
            "content-type:"
            + args.content_type
            + "\n"
            + "host:"
            + host
            + "\n"
            + "x-amz-content-sha256:"
            + payload_hash
            + "\n"
            + "x-amz-date:"
            + amzdate
            + "\n"
        )
        signed_headers = "content-type;host;x-amz-content-sha256;x-amz-date"
    else:
        canonical_headers = (
            "host:"
            + host
            + "\n"
            + "x-amz-content-sha256:"
            + payload_hash
            + "\n"
            + "x-amz-date:"
            + amzdate
            + "\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"

    canonical_request = (
        args.method
        + "\n"
        + canonical_uri
        + "\n"
        + up.query
        + "\n"
        + canonical_headers
        + "\n"
        + signed_headers
        + "\n"
        + payload_hash
    )

    algorithm = "AWS4-HMAC-SHA256"
    credential_scope = (
        datestamp + "/" + args.region + "/" + args.service + "/" + "aws4_request"
    )
    string_to_sign = (
        algorithm
        + "\n"
        + amzdate
        + "\n"
        + credential_scope
        + "\n"
        + hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    )

    signing_key = get_sig_key_v4(secret_key, datestamp, args.region, args.service)

    signature = hmac.new(
        signing_key, (string_to_sign).encode("utf-8"), hashlib.sha256
    ).hexdigest()

    authorization_header = (
        algorithm
        + " "
        + "Credential="
        + access_key
        + "/"
        + credential_scope
        + ", "
        + "SignedHeaders="
        + signed_headers
        + ", "
        + "Signature="
        + signature
    )

    if args.method == "POST" and args.content_type != "":
        headers = OrderedDict(
            [
                ("Content-Type", args.content_type),
                ("x-amz-content-sha256", payload_hash),
                ("x-amz-date", amzdate),
                ("Authorization", authorization_header),
            ]
        )
    elif args.method == "PUT" and args.content_type != "":
        headers = OrderedDict(
            [
                ("Content-Type", args.content_type),
                ("x-amz-content-sha256", payload_hash),
                ("x-amz-date", amzdate),
                ("Authorization", authorization_header),
            ]
        )
    else:
        headers = OrderedDict(
            [
                ("x-amz-content-sha256", payload_hash),
                ("x-amz-date", amzdate),
                ("Authorization", authorization_header),
            ]
        )

    if up.query == "":
        request_url = endpoint
    else:
        request_url = endpoint + "?" + up.query

    return request_url, headers


def response_content_length(response):
    """
    Get content length from response headers.
    """
    try:
        content_length = int(response.headers["content-length"])
    except KeyError:
        content_length = 0
    return content_length


def send_request(request_url, headers, args, payload):
    """
    Prints output and sends request.
    """
    if args.quiet is False:
        print("\n--[REQUEST]------------------------------------------>")
        print("Request method: %s" % args.method)
        print("Request URL: %s" % request_url)
    if args.verbose is True:
        print("Request headers: %s" % json.dumps(headers))
    if args.quiet is False:
        print("\n--[RESPONSE]----------------------------------------->")

    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    if args.method == "GET":
        response = requests.get(request_url, headers=headers, verify=args.cert_verify)
    elif args.method == "POST":
        response = requests.post(
            request_url, headers=headers, data=payload, verify=args.cert_verify
        )
    elif args.method == "PUT":
        response = requests.put(
            request_url, headers=headers, data=payload, verify=args.cert_verify
        )
    elif args.method == "HEAD":
        response = requests.head(request_url, headers=headers, verify=args.cert_verify)
    elif args.method == "DELETE":
        response = requests.delete(
            request_url, headers=headers, verify=args.cert_verify
        )
    else:
        sys.stderr.write("Error: %s is an unknown request method.\n" % args.method)
        sys.exit(1)

    if args.quiet is False:
        print("Response code: %d" % response.status_code)
        if args.verbose and len(response.cookies):
            print("Response cookies:")
            for cookie in response.cookies:
                print(cookie)
        print("Response headers: %s\n" % response.headers)
        if args.output_file != "":
            print("Writing response content to file: %s" % args.output_file)
            with open(args.output_file, "wb") as f:
                f.write(response.content)
            print("Done.")
        elif response_content_length(response) > MAX_PRINT_SIZE:
            print(
                "Response content is larger than %d bytes, not printing, "
                "consider saving to file using -of option." % MAX_PRINT_SIZE
            )
        elif response.text != "" and args.pretty_print is True:
            pr = xml.dom.minidom.parseString(response.text)
            print("Response content (pretty):\n%s" % pr.toprettyxml(indent="   "))
        elif response.text != "" and args.json_print is True:
            js = json.loads(response.text)
            print("Response content (json):\n%s" % json.dumps(js, indent=4))
        elif response.text != "":
            print("Response content:\n%s" % response.text)

    return response.status_code


def main():
    """
    Useful in case we want to call main() from another Python script.
    """
    parser = argparse.ArgumentParser(description="Simple AWS S3 request tool.")
    group1 = parser.add_mutually_exclusive_group(required=True)
    group1.add_argument(
        "-a",
        "--access",
        help="aws access key <id:secret>, eg: myid:mysecret",
    )
    group1.add_argument(
        "-t",
        "--token",
        help="aws access token",
    )
    parser.add_argument("--version", action="version", version="%(prog)s 1.0")
    parser.add_argument(
        "-m",
        "--method",
        choices=["GET", "PUT", "POST", "HEAD", "DELETE"],
        default="GET",
        help="request method (default: %(default)s)",
    )
    parser.add_argument(
        "-c",
        "--content_type",
        default="",
        help="header content-type, eg: application/octet-stream",
    )
    parser.add_argument(
        "-si",
        "--signing",
        choices=["v2", "v4"],
        default="v4",
        help="aws signing method (default: %(default)s)",
    )
    parser.add_argument(
        "-r",
        "--region",
        default="ap-southeast-1",
        help="aws region for v4 signing (default: %(default)s)",
    )
    parser.add_argument(
        "-se",
        "--service",
        default="s3",
        help="aws service for v4 signing (default: %(default)s)",
    )
    parser.add_argument(
        "-u",
        "--url",
        required=True,
        help="server url, eg: https://example.amazonaws.com:8080/bucket/foo",
    )
    parser.add_argument(
        "-cv",
        "--cert_verify",
        action="store_true",
        help="verify https cert",
    )
    group2 = parser.add_mutually_exclusive_group()
    group2.add_argument(
        "-of",
        "--output_file",
        default="",
        help="write response content to file",
    )
    group2.add_argument(
        "-pr",
        "--pretty_print",
        action="store_true",
        help="pretty print xml response content",
    )
    group2.add_argument(
        "-js",
        "--json_print",
        action="store_true",
        help="pretty print json response content",
    )
    group3 = parser.add_mutually_exclusive_group()
    group3.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help=(
            "no output except errors, exit result is set to 4 for http "
            "response code 400 and above"
        ),
    )
    group3.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show more info",
    )
    group4 = parser.add_mutually_exclusive_group()
    group4.add_argument(
        "-pf",
        "--payload_file",
        default="",
        help="payload from file",
    )
    group4.add_argument(
        "-ps",
        "--payload_string",
        default="",
        help="payload in string",
    )
    args = parser.parse_args()

    # Authentication by token.
    if args.token is not None:
        if sys.version_info[0] == 3:
            # Python 3.
            args.access = base64.b64decode(
                bytes.fromhex(args.token).decode("utf-8").strip()
            )
        else:
            # Python 2.
            args.access = base64.b64decode((args.token).decode("hex").strip())

    # Authentication by access:secret.
    access_key = ""
    secret_key = ""
    try:
        access_credentials = args.access.split(":")
        access_key = access_credentials[0]
        secret_key = access_credentials[1]
    except (IndexError, AttributeError):
        sys.stderr.write("Error: Missing access credentials.\n")
        sys.exit(1)

    # Deal with payload for POST or PUT http requests.
    payload = args.payload_string
    if args.payload_file != "":
        if os.path.exists(args.payload_file):
            with open(args.payload_file, "r") as f:
                payload = f.read()
        else:
            sys.stderr.write("Error: File %s not found.\n" % args.payload_file)
            sys.exit(1)

    # Build request depending on AWS S3 signing version.
    if args.signing == "v4":
        request_url, headers = build_request_v4(
            access_key, secret_key, args=args, payload=payload
        )
    else:
        request_url, headers = build_request_v2(access_key, secret_key, args=args)

    if args.verbose:
        up = urlparse(args.url)
        print("\n--[AUTH]--------------------------------------------->")
        if up.scheme == "https":
            print("HTTPS cert verification: %r" % args.cert_verify)
        print("AWS S3 signing: %s" % args.signing)
        print("Access Key ID: %s" % access_key)
        print("Secret Access Key: %s" % secret_key)

    # Send request and conditionally print output.
    status_code = send_request(request_url, headers, args=args, payload=payload)

    # When HTTP request response status code is in error with quiet option,
    # set exit result code, useful for bash script or similar.
    if args.quiet:
        if status_code >= 400:
            sys.exit(4)
        else:
            sys.exit(0)


if __name__ == "__main__":
    main()
