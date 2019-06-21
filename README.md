# Build state

[![Build Status](https://travis-ci.org/carblue/pkcs11.svg?branch=master)](https://travis-ci.org/carblue/pkcs11)
[![Coverage Status](https://coveralls.io/repos/github/carblue/pkcs11/badge.svg?branch=master)](https://coveralls.io/github/carblue/pkcs11?branch=master)

pkcs11
======

Twofold binding to PKCS #11 Cryptoki interface (Version 2.40 Plus Errata 01)  {1,2 PKCS#11}

configuration 'deimos': Static binding, the "import-only" C header's declarations.<br>
configuration 'derelict': Dynamic binding (DerelictUtil), the header's declarations + derelict runtime loading (any pkcs#11 implementing shared library(s)) interface.

With configuration 'derelict', the version identifier PKCS11_DYNAMIC_BINDING_ONE is set as default by dub.json, meaning, that connecting to exactly one only PKCS#11 implementing library is as easy as shown in the code snippet below. In the one-library-case, You won't have to deal with the CK_FUNCTION_LIST_PTR. There is also version identifier PKCS11_DYNAMIC_BINDING_MULTIPLE for cases, where multiple/different PKCS#11 libraries will be used by an application.
Version identifier P11KIT may be used with PKCS11_DYNAMIC_BINDING_ONE, i.a. to select the PKCS#11 implementing library via the p11-kit configuration.

For more information on dynamic binding and Your options with derelict-util, look at  {4 Derelict}.<br>
Here's some sample code:


	// Written in the D programming language
	// configuration 'derelict'
	import std.stdio;
	import pkcs11;

	int main() {
		PKCS11.load(); // uses default library: opensc-pkcs11.so/.dll {5 OpenSC}, or do specify explicitely

		CK_RV rv;
		if ((rv=C_Initialize(null)) != CKR_OK) {
			writeln("Failed to initialze Cryptoki");
			return 1;
		}
		scope(exit)
			C_Finalize(NULL_PTR);

		...
	}


[1 PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html)<br>
[2 PKCS#11 headers](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/)<br>
[3 PKCS#11 programming intro](https://www.nlnetlabs.nl/downloads/publications/hsm/hsm.pdf)<br>
[4 Derelict](http://derelictorg.github.io/overview/)<br>
[5 OpenSC, opensc.conf/debug/debug_file, inspect (high-level) Cryptoki communication](https://github.com/OpenSC/OpenSC/wiki/Using-OpenSC)<br>
[(6 Inspect (low-level) PC/SC communication)](http://ludovicrousseau.blogspot.de/2011/11/pcsc-api-spy-third-try.html)

Not yet covered: v3.0<br>
[7 PKCS#11](http://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/pkcs11-base-v3.0.html)<br>
[8 PKCS#11 headers](https://docs.oasis-open.org/pkcs11/pkcs11-base/v3.0/csprd01/include/pkcs11-v3.0/)<br>

