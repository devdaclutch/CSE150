#!/bin/bash

for file  in *; do
	if [ -f "$file" ]; then 
		filename=$(basename "$file")
		awk 'NR % 2 == 0 {print FILENAME ": " $0}' "$file"
		fi
done 
