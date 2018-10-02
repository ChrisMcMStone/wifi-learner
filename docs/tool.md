# Usage and Instructions

**Note, currently the tool only supports manual querying. I am in the process of improving the usability of the code that handles interaction with the learning tool (LearnLib). Watch this space.**

## Requirements

**Packages**: pycrypto-2.6.1 scapy-2.4.0 pycryptodomex-3.4.5

**Hardware**: Two wireless interfaces that support monitor mode.

## Usage

`sudo python Launcher.py -i <inject_interface>, -t <sniff_interface> -s <ssid> -p <pre-shared key> -m query_mode [-g gateway IP]`

Where:
- `inject_interface` and `sniff_interfaces` are the names of two wireless monitor-mode-enabled interfaces
- `ssid` is the SSID of the Access Point being tested
- `pre-shared key` is the passcode for the network
- `query_mode` is one of `file` or `socket` (see further details below)

Currently the tool only supports `file` mode (i.e. manual querying). These queries should be new-line separated in the file named `queries`. An example has been provided. 

## Query Formatting

Supported input messages are listed below. Some of these messages support parameters, which should be formatted as:

 `message_type(|param_tag=value|...)`

**For example:** 

`E2(|RSNE=cc|MIC=F|)`

The set of supported messages are:

- `DELAY`
- `DATA`
- `ENC_DATA`
- `ASSOC(|param=...|)` where `param` can only be `RSNE`
- `E2(|param=...|)` or `E4(|param=...|)` where `param` can be any of the values in the table below.

| Parameter | Tag | Values | Description |
--------------|------|---------|---------------
| Key Descriptor  | `KD`  |   `WPA1/2`, `WPA2`, `RAND` |   Indicates the EAPOL Key type: WPA, WPA2 or a random value.|
| Cipher Suites   |  `CS` |    `MD5, SHA1` |  Ciphers and hash functions used for encrypting the Key Data field and calculating the MIC. Options are MD5+RC4 or SHA1+AES. |
| RSN Element   |  `RSNE`  |   `cc, tc, ct, tt`  |   The chosen ciphersuite combination of TKIP (`t`) and CCMP (`c`) for the group and unicast traffic respectively. |
|  Key Information   | `KF` |  `P, M, S, E` | The combination of four flags in the Key Info field: `Pairwise (P)`, `MIC (M)`, `Secure (S)`, `Encrypted (E)`, or `-` when none is set. |
| Nonce  |  `NONC`  |  `W`  |  The Nonce field contains a consistent (default) or inconsistent (`W`) nonce.|
| MIC  |  `MIC`  |   `F`   |  The MIC field contains a valid (default) or invalid (`F`) Message Integrity Code.
| Replay Counter  |   `RC`  |  `W`  |    The Replay Counter is set to a correct (default) or an incorrect value (`W`).|