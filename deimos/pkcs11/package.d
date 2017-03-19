/* pkcs11.h
 * Copyright (c) OASIS Open 2016. All Rights Reserved./
 * Copyright (C) 2017  for the binding: Carsten Blüggel <carblue@geekmail.de>
 * /Distributed under the terms of the OASIS IPR Policy,
 * [http://www.oasis-open.org/policies-guidelines/ipr], AS-IS, WITHOUT ANY
 * IMPLIED OR EXPRESS WARRANTY; there is no warranty of MERCHANTABILITY, FITNESS FOR A
 * PARTICULAR PURPOSE or NONINFRINGEMENT of the rights of others.
 */

/* Latest version of the specification:
 * http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/pkcs11-base-v2.40.html
 */
/*
Written in the D programming language.
See also https://github.com/jpf91/systemd/wiki/Deimos-git-branch-structure
For git maintenance (ensure at least one congruent line with originating C header):
#define _PKCS11_H_ 1

Different from the C source which unrolls all #include of pkcs11t.h and pkcs11f.h in pkcs11.h,
the extern function decls ("extern" form of all the entry points) and
function pointer decls (typedef form of all the entry points) from pkcs11f.h are in pkcs11f.d,
the struct CK_FUNCTION_LIST is in pkcs11t.d as well as all content from pkcs11t.h.
*/

module pkcs11;


public import pkcs11.pkcs11t;
public import pkcs11.pkcs11f;

// PKCS11_DYNAMIC_BINDING_ONE / PKCS11_DYNAMIC_BINDING_MULTIPLE are mutual exclusive !
version(     PKCS11_DYNAMIC_BINDING_ONE)
	version=PKCS11_DYNAMIC_BINDING;
else version(PKCS11_DYNAMIC_BINDING_MULTIPLE)
	version=PKCS11_DYNAMIC_BINDING;

// only version(PKCS11_DYNAMIC_BINDING) needs compiling
version(PKCS11_DYNAMIC_BINDING) {

	version(PKCS11_OPENSC_SPY) enum PKCS11_OPENSC_SPY = true;
	else                       enum PKCS11_OPENSC_SPY = false;

	private {
		import std.exception : enforce;
		import derelict.util.exception,
					 derelict.util.loader,
					 derelict.util.system;

		version(P11KIT) { // use highest priority pkcs#11 module as configured by p11-kit
			static if (Derelict_OS_Windows)
				enum libNames = "libp11-kit.dll";
			else static if( Derelict_OS_Mac )
				enum libNames = "libp11-kit.dylib";
			else static if( Derelict_OS_Posix )
				enum libNames = "libp11-kit.so";
			else
				static assert( 0, "Need to implement PKCS11 libNames for this operating system." );
		}
		else {
			static if (Derelict_OS_Windows) {
				static if (PKCS11_OPENSC_SPY)
					enum libNames = "pkcs11-spy.dll";
				else
					enum libNames = "opensc-pkcs11.dll";
			}
			else static if( Derelict_OS_Mac ) {
				static if (PKCS11_OPENSC_SPY)
					enum libNames = "pkcs11-spy.dylib";
				else
					enum libNames = "opensc-pkcs11.dylib";
			}
			else static if( Derelict_OS_Posix ) {
				static if (PKCS11_OPENSC_SPY)
					enum libNames = "pkcs11-spy.so";
				else
					enum libNames = "opensc-pkcs11.so"; // onepin-opensc-pkcs11.so ?
			}
			else
				static assert( 0, "Need to implement PKCS11 libNames for this operating system." );
		}
	} // private

	class PKCS11Loader : SharedLibLoader {

		public this() {
			super( libNames );
		}

		protected override void loadSymbols() {
			bindFunc( cast(void**)&C_GetFunctionList,   "C_GetFunctionList");

		// Try to use C_GetFunctionList; an error implies, the library is not usable
			CK_FUNCTION_LIST_PTR  pFunctionList;
			enforce(C_GetFunctionList(&pFunctionList) == CKR_OK);
version(PKCS11_DYNAMIC_BINDING_ONE)
			m_function_list_ptr    = pFunctionList;

			C_Initialize           = pFunctionList.C_Initialize;
			C_Finalize             = pFunctionList.C_Finalize;
			C_GetInfo              = pFunctionList.C_GetInfo;
//		C_GetFunctionList      = pFunctionList.C_GetFunctionList;
			C_GetSlotList          = pFunctionList.C_GetSlotList;
			C_GetSlotInfo          = pFunctionList.C_GetSlotInfo;
			C_GetTokenInfo         = pFunctionList.C_GetTokenInfo;
			C_GetMechanismList     = pFunctionList.C_GetMechanismList;
			C_GetMechanismInfo     = pFunctionList.C_GetMechanismInfo;
			C_InitToken            = pFunctionList.C_InitToken;
			C_InitPIN              = pFunctionList.C_InitPIN;
			C_SetPIN               = pFunctionList.C_SetPIN;
			C_OpenSession          = pFunctionList.C_OpenSession;
			C_CloseSession         = pFunctionList.C_CloseSession;
			C_CloseAllSessions     = pFunctionList.C_CloseAllSessions;
			C_GetSessionInfo       = pFunctionList.C_GetSessionInfo;
			C_GetOperationState    = pFunctionList.C_GetOperationState;
			C_SetOperationState    = pFunctionList.C_SetOperationState;
			C_Login                = pFunctionList.C_Login;
			C_Logout               = pFunctionList.C_Logout;
			C_CreateObject         = pFunctionList.C_CreateObject;
			C_CopyObject           = pFunctionList.C_CopyObject;
			C_DestroyObject        = pFunctionList.C_DestroyObject;
			C_GetObjectSize        = pFunctionList.C_GetObjectSize;
			C_GetAttributeValue    = pFunctionList.C_GetAttributeValue;
			C_SetAttributeValue    = pFunctionList.C_SetAttributeValue;
			C_FindObjectsInit      = pFunctionList.C_FindObjectsInit;
			C_FindObjects          = pFunctionList.C_FindObjects;
			C_FindObjectsFinal     = pFunctionList.C_FindObjectsFinal;
			C_EncryptInit          = pFunctionList.C_EncryptInit;
			C_Encrypt              = pFunctionList.C_Encrypt;
			C_EncryptUpdate        = pFunctionList.C_EncryptUpdate;
			C_EncryptFinal         = pFunctionList.C_EncryptFinal;
			C_DecryptInit          = pFunctionList.C_DecryptInit;
			C_Decrypt              = pFunctionList.C_Decrypt;
			C_DecryptUpdate        = pFunctionList.C_DecryptUpdate;
			C_DecryptFinal         = pFunctionList.C_DecryptFinal;
			C_DigestInit           = pFunctionList.C_DigestInit;
			C_Digest               = pFunctionList.C_Digest;
			C_DigestUpdate         = pFunctionList.C_DigestUpdate;
			C_DigestKey            = pFunctionList.C_DigestKey;
			C_DigestFinal          = pFunctionList.C_DigestFinal;
			C_SignInit             = pFunctionList.C_SignInit;
			C_Sign                 = pFunctionList.C_Sign;
			C_SignUpdate           = pFunctionList.C_SignUpdate;
			C_SignFinal            = pFunctionList.C_SignFinal;
			C_SignRecoverInit      = pFunctionList.C_SignRecoverInit;
			C_SignRecover          = pFunctionList.C_SignRecover;
			C_VerifyInit           = pFunctionList.C_VerifyInit;
			C_Verify               = pFunctionList.C_Verify;
			C_VerifyUpdate         = pFunctionList.C_VerifyUpdate;
			C_VerifyFinal          = pFunctionList.C_VerifyFinal;
			C_VerifyRecoverInit    = pFunctionList.C_VerifyRecoverInit;
			C_VerifyRecover        = pFunctionList.C_VerifyRecover;
			C_DigestEncryptUpdate  = pFunctionList.C_DigestEncryptUpdate;
			C_DecryptDigestUpdate  = pFunctionList.C_DecryptDigestUpdate;
			C_SignEncryptUpdate    = pFunctionList.C_SignEncryptUpdate;
			C_DecryptVerifyUpdate  = pFunctionList.C_DecryptVerifyUpdate;
			C_GenerateKey          = pFunctionList.C_GenerateKey;
			C_GenerateKeyPair      = pFunctionList.C_GenerateKeyPair;
			C_WrapKey              = pFunctionList.C_WrapKey;
			C_UnwrapKey            = pFunctionList.C_UnwrapKey;
			C_DeriveKey            = pFunctionList.C_DeriveKey;
			C_SeedRandom           = pFunctionList.C_SeedRandom;
			C_GenerateRandom       = pFunctionList.C_GenerateRandom;
			C_GetFunctionStatus    = pFunctionList.C_GetFunctionStatus;
			C_CancelFunction       = pFunctionList.C_CancelFunction;
			C_WaitForSlotEvent     = pFunctionList.C_WaitForSlotEvent;
		}

version(PKCS11_DYNAMIC_BINDING_ONE) {
	__gshared CK_FUNCTION_LIST_PTR  m_function_list_ptr;

		// for (rare) cases, when it's required to pass the access to Cryptoki-functions
		@property __gshared CK_FUNCTION_LIST_PTR function_list_ptr() {
			return m_function_list_ptr;
		}
}
version(PKCS11_DYNAMIC_BINDING_MULTIPLE)
		mixin CK_FUNCTION_LIST_FENTRIES;
	} // class PKCS11Loader

version(PKCS11_DYNAMIC_BINDING_ONE) {
	__gshared PKCS11Loader          PKCS11;

	shared static this() {
		PKCS11 = new PKCS11Loader();
	}

	__gshared {
		mixin CK_FUNCTION_LIST_FENTRIES;
	}
} // version(PKCS11_DYNAMIC_BINDING_ONE)


	unittest {
		PKCS11.load("opensc-pkcs11.so");
version(PKCS11_DYNAMIC_BINDING_ONE) {
		// the following usage of function_list_ptr is not necessary in regular use cases; here only for testing purpose of @property function
		auto  p = PKCS11.function_list_ptr;
		p.C_Initialize(null);
		p.C_Finalize(null);
}
	}

} // version(PKCS11_DYNAMIC_BINDING)
