# Proof of Concept attack on SRP

This repository contains various proofs of concept of our attack on the OpenSSL big number modular exponentiation as used in SRP (Secure Remote Password). Since OpenSSL's implementation is used by several project and standard libraries, many projects are affected, as demonstrated by the few examples outlined in this repository.

Regardless of the project, as long as they use an unpatched version of OpenSSL without fixing the issue, the vulnerability can be exploited similarly. 

We recall that, within SRP, a password (a shared secret of low entropy) is involved into the ephemeral key generation process. By design, SRP resists offline dictionary attacks. However, we show that such attacks are still possible to recover the used password efficiently, by exploiting some data leakage during an insecure modular exponentiation.

Roughly speaking, the vulnerability is caused by the non constant-time nature of the function `BN_mod_exp_mont_word`.
The attack was tested on OpenSSL 1.1.1h, but should work on other versions up to OpenSSL 1.1.1i included.

## Repository layout

Each directory contains a PoC on a different project as indicated by the name. For each PoC, we designed a Dockerfile to setup the required environment (namely, get the vulnerable version of the target and meet all required dependencies). Also the core attack is the same, we add to tweak some parameters from one project to another because they did not always support all groups and sometimes differ from the SRP standard implementation.

* PoC_OpenSSL: contains the original attack, on OpenSSL implementation of SRP
* PoC_PySRP: contains the attack on the python package pysrp, used in various projects including a ProtonMail client
  
Each repository contains instructions to be able to reproduce the attack. PoC_OpenSSL contains more information about the attack, since the vulnerability comes from this implementation.

## Core idea of the attack

During the *Key commitment* part of SRP, the client computes the verifier *v = g^x mod p*, where *x* is directly related to the password (`x = H(salt, H(id:pwd))`). OpenSSL performs this operation in `SRP_Calc_client_key_ex`, through a call to `BN_mod_exp`.

Due to a lack of constant-time flags and the use of small base in SRP, the modular exponentiation method `BN_mod_exp` calls `BN_mod_exp_mont_word`.

This quick exponentiation relies on Montgomery exponentiation, using a square and multiply approach. A word `w` is used as an accumulator to perform quick operation until it overflows. 
When it first overflows, a variable is set to store the result in Montgomery form, which is then squared (using the Montgomery squaring) at each iteration, and updated whenever the word accumulator overflows.

Since the execution flow of this function varies depending on the value of the exponent, an attacker is able to recover some information on the value of the exponent. Then, the attacker leverages the leaked data in order to recover the used password by performing an offline dictionary attack, which breaks the security of SRP.

## Threat model

To exploit it, the attacker needs to be able to monitor the CPU cache, using a classical Flush+Reload attack for instance. To do so, we assume the attacker is able to deploy a spy process, with no specific privileges other than being able to read the OpenSSL dynamic library (which is a default permission).

We assume that OpenSSL was built with its default configuration: compiler optimizations are enabled, and debugging mode is disabled.

This spy process is assumed to run in background in order to record the CPU cache access to some specific functions.
