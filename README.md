pkcs11
======

Twofold binding to PKCS #11 Cryptoki interface (Version 2.40 Plus Errata 01) [1]

configuration 'deimos': Static binding, the "import-only" C header's declarations.<br>
configuration 'derelict': Dynamic binding (DerelictUtil), the header's declarations + derelict runtime loading (any pkcs#11 implementing shared library) interface.

For more information on dynamic binding and Your options with derelict-util, look at [3].<br>
Here's some sample code:


// Written in the D programming language<br>
// configuration 'derelict'<br>
import std.stdio;<br>
import pkcs11;<br>

int main() {<br>
  PKCS11.load(); // makes use of default: opensc-pkcs11.so/.dll or do specify explicitely

  CK_RV rv;<br>
  if ((rv=C_Initialize(NULL_PTR)) != CKR_OK) {<br>
    writeln("Failed to initialze Cryptoki");<br>
    return 1;<br>
  }<br>
  scope(exit)<br>
    C_Finalize(NULL_PTR);<br>

...<br>
}  


[1]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
[2]: http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/errata01/os/include/pkcs11-v2.40/
[3]: http://derelictorg.github.io/overview/
[4]: https://www.opensc-project.org/opensc/wiki/UsingOpensc
[5]: http://ludovicrousseau.blogspot.de/2011/11/pcsc-api-spy-third-try.html
