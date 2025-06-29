#!/bin/bash

#========================================================================================================
# This script automates the process of sending the python file to the proxy and running it
# Execute it by running:
# $ ./run.sh
#========================================================================================================

# Setting Password variable
pass="dkproxy"
filename="template.py" # change to the name of your python program

# SCP file onto proxy
sshpass -p $pass scp $filename dkproxy@192.168.40.80:~/dk-project/

# connect via ssh to proxy
sshpass -p $pass ssh -t dkproxy@192.168.40.80 #'echo dkproxy | sudo -S python3 ~/dk-project/template.py'

# you have to manually run the python program by typing:
# sudo python3 dk-project/template.py 