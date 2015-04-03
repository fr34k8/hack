#!/bin/bash
set -e

BIN=../tests/ctf/ezhp
#BIN=../tests/ctf/hudak
#BIN=../tests/ctf/simple
#SRC=../tests/hello.c
#SRC=../tests/algo.c

if [ "$SRC" != "" ]; then
  cd tests
  #gcc -m32 -nostdlib -static -g $src
  gcc -m32 -static -g $SRC
  BIN=../tests/a.out
  cd ../
fi


rm -f /tmp/qira_binary
ln -s $(realpath $BIN) /tmp/qira_binary
#echo "hello" | ./run_qemu.sh $BIN
#echo "4t_l34st_it_was_1mperat1v3..." | ./run_qemu.sh $BIN
#echo "i wish i were a valid key bob" | ./run_qemu.sh $BIN

pushd .
cd ./qemu/qemu-latest/
make -j32
popd

#rm -rf /tmp/qira*
#../qemu/qemu-latest/i386-linux-user/qemu-i386 -singlestep -d in_asm $@ 2> /tmp/qira_disasm
./qemu/qemu-latest/i386-linux-user/qemu-i386 -singlestep $@
ls -l /tmp/qira*

: <<'END'
echo "*** build the Program database"
time python db_commit_asm.py $BIN $SRC
#echo "*** filter the Change database"
#time python db_filter_log.py
echo "*** build the Change database"
time python db_commit_log.py
echo "*** build the memory json"
time python mem_json_extract.py
echo "*** build the pmaps database"
time python segment_extract.py
END

#python db_commit_blocks.py
#python memory_server.py
#python build_multigraph.py

