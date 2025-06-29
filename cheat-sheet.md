<!--
This is a cheat-sheet for the most important Linux-commands during the project 
-->

# Commands for SSH connection to Proxy

## simple SSH
```shell
$ ssh dkproxy@192.168.40.80
```

## SCP commands to send files

### From Proxy to Client
```shell
$ scp dkproxy@192.168.40.80:~/dk-project/tftpproxy.py . 
```
exi
### From Client to Proxy
```shell
$ scp tftpproxy.py dkproxy@192.168.40.80:~/dk-project/
```
# Network Config

following steps:
1. Select/Write the correct setting.
```shell
$ sudo nano /etc/network/interfaces
```

2. Save and close file
3. Restart network configurations
```shell
$ sudo systemctl restart networking
```
4. Check your settings
```shell
$ ip addr
```

# TFTP commands

commands:
1. establish connection to server
```shell
$ tftp 192.168.40.80
```

2. get a file (rrq)
```shell
$ get file.txt
```

3. send a file (wrq)
```shell
$ put file.txt
```
