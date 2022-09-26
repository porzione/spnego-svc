# web service to get SPENGO token

based on <https://github.com/montag451/spnego-proxy>

used go packages <https://github.com/jcmturner/gokrb5>

## How to run the service

### easy way without compilation

```text
go run main.go -debug -realm REALM.MY -user HTTP -config /etc/krb5.conf -user HTTP -domain active-namenode.domain.my -keytab ~/tmp/HTTP.keytab
```

### run with https/tls

Add command line options for private key and certificate paths, the service with listen for TLS:

```text
go run main.go -debug -realm REALM.MY -user HTTP -config /etc/krb5.conf -user HTTP -domain active-namenode.domain.my -keytab ~/tmp/HTTP.keytab -tls_key server.key -tls_crt server.crt
```

For testing purposes there is simple script `mksstls` for generating self signed pair.

### compile and run

```text
go build
./spnego-svc <OPTIONS>
```

There is simple Makefile with `release` and `build` targets.

## How to use the service

### make SPNEGO request to HDFS

```text
curl -s -H "Authorization: Negotiate $(curl -s localhost:8080/ktoken)" 'https://active-namenode.domain.my:50470/webhdfs/v1/?op=LISTSTATUS'
```

### the answer

```json
{"FileStatuses":{"FileStatus":[
{"accessTime":0,"blockSize":0,"childrenNum":1,"fileId":16386,"group":"supergroup","length":0,"modificationTime":1662640839709,"owner":"HTTP","pathSuffix":"test","permission":"755","replication":0,"storagePolicy":0,"type":"DIRECTORY"}
]}}
```

## authentication

generate password hash using python and bcrypt module

```text
python -c 'import sys, bcrypt; print(bcrypt.hashpw(sys.argv[1].encode("ascii"), bcrypt.gensalt()).decode("ascii"))' PASSWORD
```

then create auth text file with format

```text
USER:HASH
```

switch aunthentication on with `-auth` option

```text
go run main.go ... -auth AUTH_FILE_NAME
```

test it all with curl

```text
curl -i -d 'u=USER' -d 'p=PASSWORD' http://localhost:8080/ktoken
```
