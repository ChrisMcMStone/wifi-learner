# State Machine Learning of WiFi 4-Way Handshake Implementations

WiFi Learner is a tool to aid detection of logical vulnerabilities in implementations of the WiFi security handshake (a.k.a the 4-Way Handshake). The tool adopts the well studied technique of automata inference, to learn the automata (or state machine) of a given implementation of the handshake. This is done in an entirely black-box fashion, requiring only proximity to the testing device. Once the state machine has been learned, it is drawn in a human readable format for further analysis and vulnerability identification.

In this work we adapted state machine learning to handle two major limitations -- **unreliable communication mediums** and **time out behaviour**. These are both inherent properties of the 4-Way handshake. We implemented our solutions and tested 7 widely used Wi-Fi routers, finding 3 new security critical vulnerabilities: two distinct downgrade attacks and one router that can be made to leak some encrypted data to an attacker before authentication.

Further details of the research can be found in our paper [here](http://chrismcmstone.github.io/wifi-learner/publications.html).

For information on the tool, including usage instructions and supported features, see [here](https://chrismcmstone.github.io/wifi-learner/tool.html)