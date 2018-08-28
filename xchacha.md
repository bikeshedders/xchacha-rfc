%%%

    title = "XChaCha: eXtended-nonce ChaCha"
    abbr = "XChaCha"
    category = "info"
    docname = "draft-xchacha-00"
    workgroup = "(No Working Group)"
    keyword = ["security", "token"]
    
    date = 2018-08-28T16:00:00Z
    
    [[author]]
    initials="S."
    surname="Arciszewski"
    fullname="Scott Arciszewski"
    organization="Paragon Initiative Enterprises"
      [author.address]
      email = "security@paragonie.com"
      [author.address.postal]
      country = "United States"

%%%

.# Abstract

TODO

{mainmatter}

# Introduction

TODO

## Notation and Conventions

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHALL**",
"**SHALL NOT**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**", "**MAY**",
and "**OPTIONAL**" in this document are to be interpreted as described in
RFC 2119 [@!RFC2119].

# AEAD_XChaCha20_Poly1305

XChaCha20-Poly1305 is a variant of the ChaCha20-Poly1305 AEAD construction as
defined in [@!RFC7539] that uses a 192-bit nonce instead of a 64-bit nonce.

The algorithm for XChaCha20-Poly1305 is as follows:

1. Calculate a subkey from the first 16 bytes of the nonce and the key, using
   HChaCha20 ((#hchacha20)).
2. Use the subkey and remaining 8 bytes of the nonce (prefixed with 4 NUL
   bytes) with AEAD_CHACHA20_POLY1305 from [@!RFC7539] as normal.

XChaCha20-Poly1305 implementations already exist in
[libsodium](https://download.libsodium.org/doc/secret-key_cryptography/xchacha20-poly1305_construction.html),
[Monocypher](https://github.com/LoupVaillant/Monocypher),
[xsecretbox](https://github.com/jedisct1/xsecretbox),
and a standalone [Go](https://github.com/aead/chacha20) library.

## Motivation for XChaCha20-Poly1305

The nonce used by the original ChaCha20-Poly1305 is too short to safely use with
random strings for long-lived keys. XChaCha20-Poly1305 does not have this
restriction.

By generating a subkey from a 128-bit nonce and the key, a reuse of only the
latter 64 bits of the nonce isn't security-affecting, since the key (and thus,
keystream) will be different.

Assuming a secure random number generator, random 192-bit nonces should experience
a single collision (with probability 50%) after roughly 2^96 messages
(approximately 7.2998163e+28). A more conservative threshold (2^-32 chance of
collision) still allows for 2^64 messages to be sent under a single key.

Therefore, with XChaCha20-Poly1305, users can safely generate a random 192-bit
nonce for each message and not worry about nonce-reuse vulnerabilities.

As long as ChaCha20-Poly1305 is a secure AEAD cipher and ChaCha is a secure
pseudorandom function (PRF), XChaCha20-Poly1305 is secure.

## HChaCha20

**HChaCha20** is an intermediary step towards XChaCha20 based on the
construction and security proof used to create
[XSalsa20](https://cr.yp.to/snuffle/xsalsa-20110204.pdf), an extended-nonce
Salsa20 variant used in [NaCl](https://nacl.cr.yp.to).

HChaCha20 is initialized the same way as the ChaCha cipher, except that
HChaCha20 uses a 128-bit nonce and has no counter.

Consider the two figures below, where each non-whitespace character represents
one nibble of information about the ChaCha states (all numbers little-endian): 

~~~
cccccccc  cccccccc  cccccccc  cccccccc
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
bbbbbbbb  nnnnnnnn  nnnnnnnn  nnnnnnnn
~~~
Figure: ChaCha20 State: c=constant k=key b=blockcount n=nonce

~~~
cccccccc  cccccccc  cccccccc  cccccccc
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
kkkkkkkk  kkkkkkkk  kkkkkkkk  kkkkkkkk
nnnnnnnn  nnnnnnnn  nnnnnnnn  nnnnnnnn
~~~
Figure: HChaCha20 State: c=constant k=key n=nonce

After initialization, proceed through the ChaCha rounds as usual.

Once the 20 ChaCha rounds have been completed, the first 128 bits and last 128
bits of the keystream (both little-endian) are concatenated, and this 256-bit
subkey is returned.

### Test Vector for the HChaCha20 Block Function

* Key = 00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f.
  The key is a sequence of octets with no particular structure before we
  copy it into the HChaCha state.
* Nonce = (00:00:00:09:00:00:00:4a:00:00:00:00:31:41:59:27)

After setting up the HChaCha state, it looks like this:

~~~
61707865 3320646e 79622d32 6b206574
03020100 07060504 0b0a0908 0f0e0d0c
13121110 17161514 1b1a1918 1f1e1d1c
09000000 4a000000 00000000 27594131
~~~
Figure: ChaCha state with the key setup.

After running 20 rounds (10 column rounds interleaved with 10
"diagonal rounds"), the HChaCha state looks like this:

~~~
82413b42 27b27bfe d30e4250 8a877d73
4864a70a f3cd5479 37cd6a84 ad583c7b
8355e377 127ce783 2d6a07e0 e5d06cbc
a0f9e4d5 8a74a853 c12ec413 26d3ecdc
~~~
Figure: HChaCha state after 20 rounds

HChaCha20 will then return only the first and last rows, resulting
in the following 256-bit key:

~~~
82413b4 227b27bfe d30e4250 8a877d73
a0f9e4d 58a74a853 c12ec413 26d3ecdc
~~~
Figure: Resultant HChaCha20 subkey

{backmatter}

# Additional Test Vectors
