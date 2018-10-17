# StateLearner

[StateLearner](https://github.com/jderuiter/statelearner) is a tool that can learn state machines from implementations using a black-box approach. It makes use of [LearnLib](https://learnlib.de/) for the learning specific algorithms.

This is a fork of StateLearner with added support for handling lossy protocols (i.e. non-deterministism) + efficient learning of time based behaviour (e.g. timeouts and retransmissions).

This site details how to use StateLeaner for learning implementations of the WiFi security handshake. In general though, it can be used to learn arbitrary software components.

An overview of different security protocols where state machine learning has been applied can be found [here](http://www.cs.ru.nl/~joeri/StateMachineInference.html).

## Requirements

* graphviz
* WiFi-Interface Tool 

## Build

To build a JAR package, run the following command in the repository directory. 

`mvn package`

The resulting JAR will be located in the `/target/` directory. 

## Usage

`java -jar stateLearner-0.0.1-SNAPSHOT.jar <configuration file>`

An example configuration `socket.properties` has been provided for learning WiFi security handshakes. The contents of this file is explained below.

Other example configurations can be found in the 'examples' directory.

## Configuration

Configuration parameters specified in the required `config` file include:

| Parameter | Options | Explanation |
|-----------|---------|-------------
| type | `socket`, `smartcard`, `tls` | There is built in support for testing TLS and Smartcards. For everything else, interaction is done over a socket.|
| hostname | `ip addr` | IP address of machine running learner interface (e.g. [WiFi](https://github.com/ChrisMcMStone/wifi-learner)). If run locally, then `127.0.0.1`.|
| port | `port no` | Port number of corresponding service running on above IP address |
| alphabet | ... | Space separated list of all input commands to use when learning target state machine |
| learning_algorithm | `lstar`, `ttt` etc.. | Learning algorithm to use. |
| eqtest | `wmethod`,`wpmethod`,`randomwords` | Equality checking algorithm/Counter Example finder. These require additional parameters, as shown in example config files. |
| use_cache | `true`, `false` | Uses a database cache to handle protocols that are lossy or seem to behave non-deterministically |
| expected_flows | \[{query:response}\] | List of expected query-response traces from the target protocol. This overcomes situations where the protocol implementation may be particularly lossy. 
| time_learn | `true`, `false` | Improves efficiency for learning time aspects of a protocol. |
| disable_outputs | .... | Space separated list of outputs that can be assumed reset the protocol. For example, a disconnect message. |
| retrans_enabled | .... | Space separated list of inputs that are to be enabled when a message retransmission is observed. For example, you may only want to `DELAY`, i.e. wait for a new message or a timeout. |