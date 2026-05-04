#!/bin/bash
sudo iptables -S | awk '
    /^-A bl_/ { count[$2]++ }
    END {
        total = 0
        for (c in count) { print c, count[c]; total += count[c] }
        if (total > 0) { print ""; print "TOTAL", total }
        else print "No blocklists found"
    }
'
