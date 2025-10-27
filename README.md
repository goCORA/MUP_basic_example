# MUP_basic_example
OTPs have long been identified as perfect encryption, however, they have limitations that have made them impractical. MUPs (Multiple Use Pads) are reusable OTPs that are practical and ideal. 

This is a very basic and simple example that simply demonstrates that the removal of a language and plaintext patterns from messages that then have a pad applied to them
results in unbreakable encryption. CORA has found countless methods of removing these patterns, each with associated advantages and disadvantages. 
The current implementation of CORA embodies the best practices untile Generation 3 emerges.

# How does the program work?
As a demonstation, it is very simple. It requires that pycryptodome be installed, ideally in a virtual environment. Then simply run the program.

There are two pipelines:
A - two messages are encrypted using the same OTP (XOR operation). Then these two ciphertexts are XORed together which removed the OTP and results in the
XOR of the two original messages. Using language and plaintext patterns, the original messages may be extracted. Being a simple example, the crib dragging
is basic and simply demonstrates that it is possible.
B - a fast and simple 16 byte (128 bit) AES-CTR encryption operates on both messages first, and then the same MUP (pad) operates on these ciphertext, 
resulting in "unbreakable encryption". The same process as used with A above is used, without success.

It should be noted that, once a single message is broken, the original OTP can be obtained. In contrast, since messages will not be recovered using MUPs,
even though it is removed when two ciphertexts are XORed together, the MUP will not be recovered and is therefore safe for reuse. 

Morever CORA uses additional techniques to ensure a probabilistic improbability that MUPs are morphed during reuse.

# White Paper
CORAcsi.com has evolved MUPs over that past decade. 
The White Paper "CORA - patterns and probabilities" is freely available.
