# Test fixtures: do not use outside tests

`preparams-*.json` are Paillier keys and safe primes for the three test
parties, cached because generating them takes minutes. They are **public test
data** and committed to the repo so CI is fast. Never use them in a real
signer: `signerd` generates fresh pre-parameters for every key generation.

Delete the files to regenerate them on the next `go test` run.
