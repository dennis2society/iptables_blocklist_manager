#!/bin/bash
sudo ip6tables -S | awk '/^-A bl_/ {count[$2]++} END {for (c in count) print c, count[c]}'
