#!/bin/bash
# Display the number of networks (CIDRs) per ipset blocklist, plus total.
sudo ipset list | awk '
    /^Name: bl_/           { name = $2 }
    /^Number of entries:/ { count[name] = $4; total += $4 }
    END {
        for (s in count) print s, count[s]
        print "\nTOTAL", total
    }
'
