#!/bin/bash 
if [ -d $(pwd)/root ];then
  echo MachshilimLite.py -p "$1" -r $(pwd)/root
  nohup python MachshilimLite.py -p "$1" -r $(pwd)/root &
else
 echo MachshilimLite.py -p "$1" -r "$2"  
 nohup python MachshilimLite.py -p "$1" -r "$2" &
fi