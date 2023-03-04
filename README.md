# Schnorr-signatures

Schnorr signatures are a type of digital signature algorithm used in cryptography to verify the authenticity of digital messages or documents. They were introduced by the German mathematician Claus-Peter Schnorr in 1989 and are based on the discrete logarithm problem.

Schnorr signatures have several advantages over other types of digital signature algorithms, such as their smaller size and faster verification time. They also support a feature called signature aggregation, which allows multiple signatures to be combined into a single signature, reducing the amount of data required to verify a set of signatures.

In Bitcoin, Schnorr signatures are expected to be implemented as a new signature algorithm to replace the current ECDSA signature algorithm. This is because Schnorr signatures provide greater security, privacy, and scalability benefits compared to ECDSA signatures. In particular, Schnorr signatures will allow for the creation of more complex multi-signature schemes, which will enhance Bitcoin's functionality and use cases.

# src.cpp

This code generates a random key pair, signs a message "Hello, world!" using the Schnorr signature algorithm, verifies the signature, and prints out the results.
