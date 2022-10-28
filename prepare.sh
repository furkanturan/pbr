#!/bin/bash

git clone https://github.com/relic-toolkit/relic.git
cd relic
export RELIC_LOC=$(pwd)
./preset/gmp-pbc-bls381.sh
make 
echo "export RELIC_LOC="$RELIC_LOC > ../source_me
echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH:"$RELIC_LOC"/lib" >> ../source_me
echo "export DYLD_LIBRARY_PATH=$LD_LIBRARY_PATH:"$RELIC_LOC"/lib" >> ../source_me