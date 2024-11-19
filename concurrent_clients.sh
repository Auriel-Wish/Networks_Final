#/bin/bash

rm -f example.txt dragon.txt

curl --proxy localhost:1026  --cacert ca.crt https://en.wikipedia.org/wiki/Dragon_Spacecraft_Qualification_Unit > dragon.txt &

curl --proxy localhost:1026  --cacert ca.crt https://example.com > example.txt &

if [ -s example.txt ]; then
    # The file is not empty
    echo "Test PASSED\n"

else
    # The file is empty
    echo "Test FAILED\n "


fi

