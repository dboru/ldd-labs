# ldd-labs

'tcptat.c’
 is  kernel module  program which exposes TCP internal parameters such as total_retrans, snd_cwnd, srtt, and rttvar. It uses kprobes to monitor TCP ‘tcp_rcv_established’ function and collect TCP kernel parameters. The statistics are exposed using Netlink communication mechanism to a userspace program. Netlink is chosen since it provides a full duplex communication between kernel space and user space based on a socket API.
  The module collects TCP internal parameters for 100 TCP connections by default. A configurable module parameter ‘maxflows’ is also provided  so that the user can set to desired value.  
The module is functionally limited since it returns a log for all TCP connections it has seen  and does not have a an option to return the statistics  for a given TCP connection. It also maintains the statistics even if the connection is closed unless the user reloads the module.
 tcpinfo.c 
     is  a user space program that communicates with the kernel module to collect TCP kernel parameters.

