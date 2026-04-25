#!/bin/bash
# This script is necessary to delete >85000 CSV files in this folder
# (argument list too long error)

find . -name "*.csv" -print0 | xargs -0 rm
