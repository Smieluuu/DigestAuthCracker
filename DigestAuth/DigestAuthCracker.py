from hashlib import md5, sha256, sha3_512, sha3_384, sha512, sha224, sha384, blake2b, blake2s 


header = 'Authorization: Digest username="...",realm="...", nonce="...", uri="/...", qop=..., response="...", algorithm=...'

realm = header.split('realm="')[1].split('"')[0]
username = header.split('username="')[1].split('"')[0]
uri = header.split('uri="')[1].split('"')[0]
nonce = header.split('nonce="')[1].split('"')[0]
responseHeader = header.split('response="')[1].split('"')[0]

with open('rockyou.txt', 'r', encoding=("latin-1")) as f:
    passwords = f.read().split("\n")


funcions = [md5, sha256, sha3_512, sha3_384, sha512, sha224, sha384, blake2b, blake2s]
methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'CONNECT', 'TRACE']

for password in passwords:
    for function in funcions:
        for method in methods:
                    # username:realm:password
            A1 = username + ':' + realm + ':' + password
            A1 = function(A1.encode('utf-8')).hexdigest()

                    # method:uri
            A2 = method + ':' + uri
            A2 = function(A2.encode('utf-8')).hexdigest()

                    # response = function(A1:nonce:A2)
            response = A1 + ':' + nonce + ':' + A2
            response = function(response.encode('utf-8')).hexdigest()

            if response == responseHeader:
                print("Password found: " + password)
                print("Hash: " + response)
                print("Function: " + function.__name__)
                print("Method: " + method)
                break
