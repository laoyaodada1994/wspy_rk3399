#!/bin/sh
ftp -v -n 192.168.3.96<<EOF
user sinux eibiozubooy4
get $1 ./readme.md
bye
EOF

# lcd ~/Downloads