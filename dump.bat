chcp 65001
PATH=%PATH%;C:\Program Files\Wireshark;

dumpcap -D
pause

dumpcap -i "福能網路" -b filesize:50000 -b duration:3600 -w output.pcapng
pause