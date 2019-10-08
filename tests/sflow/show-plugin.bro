# @TEST-EXEC: bro -NN RLABS::SFLOW |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
