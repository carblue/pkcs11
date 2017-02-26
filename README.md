# Build state

[![Build Status](https://travis-ci.org/carblue/pkcs11.svg?branch=master)](https://travis-ci.org/carblue/pkcs11)
[![Coverage Status](https://coveralls.io/repos/github/carblue/pkcs11/badge.svg?branch=master)](https://coveralls.io/github/carblue/pkcs11?branch=master)

pkcs11
======

Twofold binding to PKCS #11 Cryptoki interface (Version 2.40 Plus Errata 01) [1 PKCS#11]

configuration 'deimos': Static binding, the "import-only" C header's declarations.<br>
configuration 'derelict': Dynamic binding (DerelictUtil), the header's declarations + derelict runtime loading (any pkcs#11 implementing shared library) interface.

For more information on dynamic binding and Your options with derelict-util, look at [4 Derelict].<br>
Here's some sample code:


// Written in the D programming language<br>
// configuration 'derelict'<br>
import std.stdio;<br>
import pkcs11;<br>

int main() {<br>
  PKCS11.load(); // makes use of default: opensc-pkcs11.so/.dll [5 OpenSC] or do specify explicitely

  CK_RV rv;<br>
  if ((rv=C_Initialize(NULL_PTR)) != CKR_OK) {<br>
    writeln("Failed to initialze Cryptoki");<br>
    return 1;<br>
  }<br>
  scope(exit)<br>
    C_Finalize(NULL_PTR);<br>

...<br>
}

[1 PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)<br>
[2 PKCS#11 headers](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/)<br>
[3 PKCS#11 programming intro](https://www.nlnetlabs.nl/downloads/publications/hsm/hsm_node9.html)
[4 Derelict](http://derelictorg.github.io/overview/)<br>
[5 OpenSC, opensc.conf/debug/debug_file, inspect (high-level) Cryptoki communication](https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC)<br>
[(6 Inspect (low-level) PC/SC communication)](http://ludovicrousseau.blogspot.de/2011/11/pcsc-api-spy-third-try.html)
