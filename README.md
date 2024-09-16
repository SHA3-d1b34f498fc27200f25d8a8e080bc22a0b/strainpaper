# Strain
This is the source code for the evaluation section of paper

<em>Erik-Oliver Blass, Florian Kerschbaum, “Strain: A Secure Auction for Blockchains”, Proceedings of European Symposium on Research in Computer Security (ESORICS’18), Barcelona, Spain, ISBN 978-3-319-99072-9, 2018</em> [(Link)](https://dl.acm.org/doi/abs/10.1007/978-3-319-99073-6_5)

# Environment:
Ubuntu 16.04 LTS  
Python 2.7.12  
pycrypto 2.6.1  
gmpy2 2.0.7  

# Runnable files:
$ python testGM.py  
$ python testProofs.py  
$ python auction.py  

Comment or uncomment tests in the files above, as needed.

# Benchmark:

The runtime of the auction is $O(s^2)$ where $s$ is the number of suppliers.  
With 5 suppliers, the auction takes about 4 minutes.

# Pitfalls:
proof_eval and verify_eval are executed, but they do not work against malicious adversaries.
