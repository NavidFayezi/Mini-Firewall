# Mini-Firewall
In this assignment, I will be using the code snippet [here](https://www.netfilter.org/projects/libnetfilter_queue/doxygen/html/nfqnl__test_8c_source.html), which reads packets from the kernel queue and returns them after the processing is completed. The mini-firewall will inspect inbound UDP packets, and writes the information of the target packets to a file. Target packets are those whose **Source IP address** and **Source port** match the IP address and port number given by the user as inputs.

## Compile and run
Make sure that *libnetfilter_queue*, *libnfnetlink*, and *libmnl* are installed and the kernel version is 3.6 or later.  
`sudo apt install libnetfilter-queue-dev`  
`sudo apt install libnfnetlink-dev`  
`sudo apt install libmnl-dev`

Next, make the shell scripts executable.  
`chmod 777 add_rule.sh`  
`chmod 777 delete_rule.sh`  

After that, Link the library while compiling *main.c*.  
`gcc main.c -lnetfilter_queue -o output`

Finally, run the program. Do not forget *sudo*. Give an IP address, a port number, a number in range of [0 - 65535] as the number of iterations, and a string, all as the arguments for the main function. For example:  
`sudo ./output 192.168.1.1 53 5 hello`

### Warning!
1. You might need to switch to the legacy mode if you get the following error while adding rules to *iptables*:  
`iptables v1.8.7 (nf_tables):  RULE_APPEND failed (No such file or directory): rule in chain INPUT`  
In this case, switch to the legacy mode using:  
`update-alternatives --set iptables /usr/sbin/iptables-legacy`  
and run the program again.
 2. If you kill the program before it executes *delete_rule.sh*, you will need to manually delete the rule that was added to *iptables* by *add_rule.sh*. 