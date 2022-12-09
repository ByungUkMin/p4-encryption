

<img src="purdue-cs-logo.jpg" alt="drawing" width="450"/>

# Validating and Evaluating the Paper, "Implementing AES Encryption on Programmable Switches via Scrambled Lookup

**Members:** Franklin Liu, Tom Yarrow, Rui Zhu, Siyu Yao, Byounguk Min, Winston Wang

## Project Statement

We seek to extend the results of "Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables" by Xiaoqi Chen using multiple mininet hosts and multiple ONOS switches utilizing programmed with p4 for encryption and decryption. While the original paper only supported a one way encryption between two hosts and one switch, we aim to extend our implementation to more complex topologies while also supporting decryption.

## Advanced Encryption Standard

Advanced Encryption Standard (AES) is a symmetric-key encryption algorithm specified by the U.S. National Institute of Standards and Technology since 2001. Built on the idea of substituion-permutation networks, AES encrypts data block by block into equivalent sized ciphertext using repeated rounds of encryption. Data block size and key size can both be varied, with the standard variants being AES-128, AES-192, and AES-256, respectively.

While a successful AES implementation in the data plane would be helpful for a number of security annd privacy applications, the nature of the algorithm's round by round, block by block encryption strategy makes implementation on standard programmable switches a difficult task for such devices with limited processing power when even AES-128 requires 10 rounds of encryption.

The key insight of "Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables", then, was the utilization of Scrambled Lookup Tables to take advantage of table-matching to reduce the number of arithmetic operations required for encruption.


https://user-images.githubusercontent.com/54554850/206609500-cfd5bb17-efe5-4ebe-b85b-af96a8ff368b.mp4

(swap out for extended video later?)

## Our Implementation and Results

Our implementation was run on an AWS EC2 instance with 2vCPU and 8 gb of of memory, and utilizes a 2 switch, 6 host Mininet topology heavily drawing upon the assignment 3 code repository with custom Scapy scripts for packet generation and for collecting metrics such as packect rate to measure encryption overhead.

(insert results here)

## p4-projects
Directories from the paper "Implementing AES Encryption on Programmable Switches via Scrambled Lookup Tables"

Actual code for the encryption is in p4-encryption/p4-projects/AES-tofino directory.

## Source Code Repository: 

https://github.com/ByungUkMin/p4-encryption/

