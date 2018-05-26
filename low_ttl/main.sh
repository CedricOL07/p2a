#!/usr/bin/env sh

./server.py &

tshark -q -i lo -Y "tcp && tcp.dstport==7777 && tcp.len==0" -c 10 -T pdml > tmp_cap.pdml &

sleep 2

./client.py &

sleep 3

SRCPORT=$(cat tmp_cap.pdml | egrep tcp.srcport | egrep -o 'show="[0-9]+' | egrep -o [0-9]+ | tail -n 1)
DSTPORT=$(cat tmp_cap.pdml | egrep tcp.dstport | egrep -o 'show="[0-9]+' | egrep -o [0-9]+ | tail -n 1)
SEQ=$(cat tmp_cap.pdml | egrep tcp.seq | egrep -o 'value="[0-9a-f]+' | egrep -o [a-f0-9]+$ | tail -n 1)
ACK=$(cat tmp_cap.pdml | egrep tcp.ack | egrep -o 'value="[0-9a-f]+' | egrep -o [a-f0-9]+$ | tail -n 1)

./attack_script.py $SRCPORT $DSTPORT $SEQ $ACK

sleep 4
