#!/bin/bash
cd src/
javac kuroro/security/*.java
if [ -f ./../dist/signer.jar ]; then
  rm ./../dist/signer.jar
fi
jar -cfm ./../dist/signer.jar manifest assets/ kuroro/security/*.class ./../LICENSE
rm kuroro/security/*.class
