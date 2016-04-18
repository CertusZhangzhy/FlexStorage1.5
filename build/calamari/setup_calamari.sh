#!/usr/bin/expect -f
#################################################
#usage:
#./setup_calamari.sh username email password
#example:
#./setup_calamari.sh root root@gmail.com secret
################################################
set timeout 120
set username [lindex $argv 0]
set email [lindex $argv 1]
set password [lindex $argv 2]
spawn calamari-ctl initialize

    expect {
        "*Complete*" {exit 0}
        "*):" {send "$username\r"}
    }

    expect "Email address"
    send "$email\r"

    expect "Password*"
    send "$password\r"

    expect "Password*again*"
    send "$password\r"

interact
