#!/bin/bash
sudo ip6tables -S | awk '
    /^-A bl_/ { count[$2]++ }
    END {
        total = 0
        for (c in count) { print c, count[c]; total += count[c] }
        print "\nTOTAL", total
    }
'
