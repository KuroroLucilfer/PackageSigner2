# Package Signer 2 [![LICENSE](https://img.shields.io/badge/license-Apache%202-red.svg)](https://www.apache.org/licenses/LICENSE-2.0)
A command line tool to automatically sign APKs and OTA update packages with the Android test certificate and private key.


## Usage
Executing from command line:
```
Usage: java -jar signer.jar [-w] [package]
```

Example:
```
$ java -jar signer.jar -w update.zip
```

or
```
$ java -jar signer.jar application.apk
```

Verify the package:
```
$ jarsigner -verify update_signed.zip
```


## Build
Building from source:
```
$ ./build.sh
```
