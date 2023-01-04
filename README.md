# CRAQ-Verified
Verification of the CRAQ protocol in Ivy, following the Sift methodology (Ma et. al, usenix ATC '22). Final project for COS516 Fall 22. 

Dependencies: A working installation of Ivy version 1.8.24, GNU G++

To run the ivy checker: `ivy_check craq_system.ivy` 

To compile extracted c++: `g++ -Wno-parentheses-equality -pthread -std=c++11 -o craq craq_system.cpp`

Usage: `./craq [number of replicas] [replica id]`

You can open up a new terminal for each instance and manually invoke `server.system.set([integer key], "[your value here]")` or `server.system.get([integer key])` using the read, eval, print interface.

Alternatively, to compile benchmark client: `g++ -Wno-parentheses-equality -pthread -std=c++11 -o craq_client craq_client.cpp`

Usage: `./craq_client [number of replicas]`

Be sure to spin up the replicas first before the client. 

**Disclaimer:** Using the client leads to poor system performance, the reason for this is currently unknown. 

