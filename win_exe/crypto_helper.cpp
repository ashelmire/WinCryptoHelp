#include "crypto_helper.h"
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
// The RSA public-key key exchange algorithm
#define ENCRYPT_ALGORITHM         CALG_RSA_KEYX
// The high order WORD 0x0200 (decimal 512)
// determines the key length in bits.
#define KEYLENGTH                 0x02000000
#define BLOCK_LEN 128


//--------------------------------------------------------------------
// The constructor initializes the member variables
// to NULL.
//--------------------------------------------------------------------
CryptoHelper::CryptoHelper()
{
	printf("[+] creating CryptoHelper\n");
	m_hCryptProv = NULL;
	m_hCryptKey   = NULL;
}
//--------------------------------------------------------------------
// The destructor releases the handles acquired
// when an object goes out of scope.
//--------------------------------------------------------------------
CryptoHelper::~CryptoHelper()
{
       if (m_hCryptProv)
       {
              CryptReleaseContext(m_hCryptProv,0);
              m_hCryptProv = NULL;
       }
       if (m_hCryptKey)
              m_hCryptKey = NULL;
}

//--------------------------------------------------------------------
// This method calls the CryptAcquireContext function
// to get a handle to a key container owned by the the
// Microsoft Enhanced Cryptographic Provider.
//--------------------------------------------------------------------
HRESULT CryptoHelper::AcquireContext(LPCTSTR wszContainerName)
{
	HRESULT       hr = S_OK;
	DWORD         dwErrCode;
	// Release a previously acquired handle to the key container.
	if (m_hCryptProv != NULL)
	{
		CryptReleaseContext(m_hCryptProv,0);
		m_hCryptProv = NULL;
	}
	// Release a previously acquired handle to key-pair.
	if (m_hCryptKey != NULL)
		m_hCryptKey = NULL;
	// Attempt to acquire a context and a key container.
	// The context will use Microsoft Enhanced Cryptographic
	// Provider for the RSA_FULL provider type.
	if(!CryptAcquireContext(&m_hCryptProv,
		wszContainerName,
		MS_ENH_RSA_AES_PROV, // was MS_ENHANCED_PROV
		PROV_RSA_AES, // was PROV_RSA_FULL
		CRYPT_MACHINE_KEYSET))
	{
		// An error occurred in acquiring the context. This could mean
		// that the key container requested does not exist. In this case,
		// the function can be called again to attempt to create a new key
		// container.
		if (GetLastError() == NTE_BAD_KEYSET)
		{
			printf("[-] BAD KEYSET. Trying NEWKEYSET.\n");
			if(!CryptAcquireContext(&m_hCryptProv,
								wszContainerName,
								MS_ENH_RSA_AES_PROV,   PROV_RSA_AES, //was MS_ENHANCED_PROV, PROV_RSA_FULL
								CRYPT_MACHINE_KEYSET|CRYPT_NEWKEYSET))
			{
				dwErrCode = GetLastError();
				printf("[-] Still BAD KEYSET with CRYPT_NEWKEYSET option\n");
				return HRESULT_FROM_WIN32(dwErrCode);
			}
		}
		else
		{
			dwErrCode = GetLastError();
			return HRESULT_FROM_WIN32(dwErrCode);
		}
	}
	return hr;
}
//--------------------------------------------------------------------

// This method calls the CryptGenKey function to get a handle to an

// exportable key-pair. The key-pair is  generated with the RSA public-key
// key exchange algorithm using Microsoft Enhanced Cryptographic Provider.
//--------------------------------------------------------------------
HRESULT CryptoHelper::GenerateKeyPair()
{
	HRESULT       hr = S_OK;
	DWORD         dwErrCode;
	// If the handle to key container is NULL, fail.
	if (m_hCryptProv == NULL)
		return E_FAIL;
	// Release a previously acquired handle to key-pair.
	if (m_hCryptKey)
		m_hCryptKey = NULL;
	// Call the CryptGenKey method to get a handle
	// to a new exportable key-pair.
	if(!CryptGenKey(m_hCryptProv,
                ENCRYPT_ALGORITHM,
				KEYLENGTH | CRYPT_EXPORTABLE,
				&m_hCryptKey))
	{
		dwErrCode = GetLastError();
		return HRESULT_FROM_WIN32(dwErrCode);
	}
	return hr;
}
//--------------------------------------------------------------------
// This method calls the CryptExportKey function to get the Public key
// in a byte array. The byte array is allocated on the heap and the size
// of this is returned to the caller. The caller is responsible for releasing // this memory using a delete call.
//--------------------------------------------------------------------
HRESULT CryptoHelper::ExportPublicKey(BYTE **ppPublicKey, DWORD &cbKeySize)
{
       // HRESULT hr = S_OK;
       DWORD    dwErrCode;
       DWORD dwBlobLen;
       BYTE *pbKeyBlob = NULL;
       // If the handle to key container is NULL, fail.
       if (m_hCryptKey == NULL)
              return E_FAIL;
       // This call here determines the length of the key
       // blob.
       if(!CryptExportKey(
                 m_hCryptKey,
                 NULL,
                 PUBLICKEYBLOB,
                 0,
                 NULL,
                 &dwBlobLen))
       {
              dwErrCode = GetLastError();
              return HRESULT_FROM_WIN32(dwErrCode);
       }
       // Allocate memory for the pbKeyBlob.
       if((pbKeyBlob = new BYTE[dwBlobLen]) == NULL)
       {
              return E_OUTOFMEMORY;
       }
       // Do the actual exporting into the key BLOB.
       if(!CryptExportKey(
                 m_hCryptKey,
                 NULL,
                 PUBLICKEYBLOB,
                 CRYPT_OAEP,
                 pbKeyBlob,
                 &dwBlobLen))
       {
              delete pbKeyBlob;
              dwErrCode = GetLastError();
              return HRESULT_FROM_WIN32(dwErrCode);
       }
       else
       {
               *ppPublicKey = pbKeyBlob;
               cbKeySize = dwBlobLen;
       }
       return S_OK;
}
//--------------------------------------------------------------------
// This method calls the CryptExportKey function to get the Private key
// in a byte array. The byte array is allocated on the heap and the size
// of this is returned to the caller. The caller is responsible for releasing // this memory using a delete call.
//--------------------------------------------------------------------
HRESULT CryptoHelper::ExportPrivateKey(BYTE **ppPrivateKey, DWORD &cbKeySize)
{
       HRESULT       hr = S_OK;
       DWORD         dwErrCode;
       DWORD dwBlobLen;
       BYTE *pbKeyBlob;
       // If the handle to key container is NULL, fail.
       if (m_hCryptKey == NULL)
              return E_FAIL;
       // This call here determines the length of the key
       // blob.
       if(!CryptExportKey(
                 m_hCryptKey,
                 NULL,
                 PRIVATEKEYBLOB,
                 0,
                 NULL,
                 &dwBlobLen))
       {
              dwErrCode = GetLastError();
              return HRESULT_FROM_WIN32(dwErrCode);
       }
       // Allocate memory for the pbKeyBlob.
       if((pbKeyBlob = new BYTE[dwBlobLen]) == NULL)
       {
              return E_OUTOFMEMORY;
       }

       // Do the actual exporting into the key BLOB.
       if(!CryptExportKey(
                 m_hCryptKey,
                 NULL,
                 PRIVATEKEYBLOB,
                 0,
                 pbKeyBlob,
                 &dwBlobLen))
       {
              delete pbKeyBlob;
              dwErrCode = GetLastError();
              return HRESULT_FROM_WIN32(dwErrCode);
       }
       else
       {
               *ppPrivateKey = pbKeyBlob;
               cbKeySize = dwBlobLen;
       }

	   DWORD pcbEncoded;
	   BYTE* pbEncoded;

	   if ( ! CryptEncodeObject( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbKeyBlob, NULL, &pcbEncoded))
		   printf("[-] CryptEncode to check size of PublicKeyBlob failed. Err: %s", GetLastError());
	   else{

		   if(! (pbEncoded = (BYTE*)malloc(pcbEncoded))){
			   printf("[-] malloc X509 data failed. Err: %s\n", GetLastError());
			   return -1;
		   }
		   if ( ! CryptEncodeObject( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY, pbKeyBlob, pbEncoded, &pcbEncoded)){
			   printf("[-] CryptEncode object failed. Err: %s\n", GetLastError());
			   return -1;
		   }

		   printf("\nPrivKeyX509Export DER format= \"");
		   for (int i=0; i < pcbEncoded; i++)
		   {
			      printf("%02x", pbEncoded[i]);
		   }
		   printf("\"\n\n");
	   }
       return hr;
}

HCRYPTKEY CryptoHelper::GenerateAESKey(BYTE *pbPublicKey, DWORD dwPublicKeySize, BYTE **hAes, DWORD &cbKeySize, BYTE *pbPrivateKey, DWORD dwPrivateKeySize){

	HCRYPTKEY hKey;         // Session key handle
	HCRYPTKEY hRSAKey;         // RSA key handle
	BYTE *pbKeyBlob;        // Pointer to a simple key BLOB
	DWORD dwBlobLen;        // The length of the key BLOB

	if(CryptAcquireContext(
	   &m_hCryptProv,
	   NULL,
	   NULL,
	   PROV_RSA_AES,
	   CRYPT_VERIFYCONTEXT))
	{
		printf("[+]The CSP has been acquired. \n");
	}
	else
	{
		printf("[-] Error during CryptAcquireContext. err: %s", GetLastError());
	}

	if ( !CryptImportKey(m_hCryptProv, pbPrivateKey, dwPrivateKeySize, NULL, NULL, &hRSAKey)){
		printf("[-] Failed to Import Public Key. Err: %s\n", GetLastError());
		return -1;
	}


	if (CryptGenKey(
		m_hCryptProv, //hProv,
		CALG_AES_128,
		CRYPT_EXPORTABLE,
		&hKey))
	{
		printf("[+] Original AES session key is created. \n");
	}
	else
	{
		printf("ERROR -- CryptGenKey of AES session key. err: %s", GetLastError());
	}

	if (!CryptExportKey(hKey, hRSAKey, SIMPLEBLOB, 0, 0, &dwBlobLen)){
		printf("[-] Error in initializing key export. err: %s", GetLastError());
		return -1;
	}
	if (!(pbKeyBlob = (BYTE *)LocalAlloc(LMEM_FIXED, dwBlobLen))){
		printf("[-] Out of memory in export key\n");
		return -1;
	}
	if (!CryptExportKey(hKey, hRSAKey, SIMPLEBLOB, 0, pbKeyBlob, &dwBlobLen)){
		printf("[-] Error Exporting Simple blob. err: %s\n", GetLastError());
		return -1;
	}
	*hAes = pbKeyBlob;
	cbKeySize = dwBlobLen;

	// Print out the encrypted AES key SIMPLEBLOB to console as a
	// hexadecimal string.
	printf("\nAesKeyExport SIMPLEBLOB = \"");
	for (int i=0; i < cbKeySize; i++)
	{
		printf("%02x", pbKeyBlob[i]);
	}
	printf("\"\n");

	BYTE *pbData;

	pbData = SpcExportRawKeyData(m_hCryptProv, hKey, hRSAKey, &cbKeySize);
	printf("AesKeyExport Raw = \"");
	for (int i=0; i < cbKeySize; i++)
	{
		printf("%02x", pbData[i]);
	}
	printf("\"\n\n");


	/*
	TODO: This is bad programming. Put all of this encryption work into it's own function.
	*/
	DWORD bufLen = BLOCK_LEN; // buffer length
	DWORD outLen = 0; // Length of encrypted data
	PBYTE pbEncBuffer = NULL;
	HCRYPTHASH hHash;
	BOOL Final = FALSE;

	if(pbEncBuffer = (BYTE *)malloc(bufLen)){
		printf("[+] Alloc'd enc / dec buffer.\n");
	} else {
		printf("[-] Alloc enc / dec buffer Failed. err: %s\n", GetLastError());
	}
	char *msg = "You have read the secret";
	printf("Plaintext message is: %s\n", msg);
	DWORD msg_len = sizeof(msg);
	outLen = strlen(msg) + 1;

	memset(pbEncBuffer, 0, 128);
	memcpy(pbEncBuffer, msg, outLen);

	if(! CryptCreateHash(m_hCryptProv, CALG_SHA1, 0, 0, &hHash)){
		printf("[-] Failed to create hash. err: %s", GetLastError());
	}
	Final = TRUE;
	printf("Encrypting the string: %s\n", pbEncBuffer);
	if (!CryptEncrypt(hKey, hHash, Final, 0, pbEncBuffer, &outLen, bufLen)){
		printf("[-] CryptEncrypt Failed. err: %s\n", GetLastError());
		return -1;
	}
	printf("[+] Encrypted Size is: %d\n", outLen);
	LPCSTR outFilename = "enc.bin";

	//Open file for writing.
	HANDLE hOutFile = CreateFile(outFilename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hOutFile == INVALID_HANDLE_VALUE){
		printf("[-] Failed to open output file. err: %s\n", GetLastError());
		return -1;
	}

	DWORD written = 0;
	if(!WriteFile(hOutFile, pbEncBuffer, outLen, &written, NULL)){
		printf("[-] WriteFile failed. err: %s\n", GetLastError());
	}
	CloseHandle(hOutFile);
	printf("[+] File Written.\n");

	return hKey;
}

HRESULT CryptoHelper::AESEncryptFile(HCRYPTKEY hAes, LPCSTR lpszInFile, LPCSTR lpszOutFile){
	/*
	TODO: Implement this.
	*/
	return 0;
}

BYTE *CryptoHelper::SpcExportRawKeyData(HCRYPTPROV hProvider, HCRYPTKEY hKey, HCRYPTKEY hExpKey, DWORD *cbData) {
  BOOL      bResult = FALSE;
  BYTE      *pbData = 0, *pbKeyData;

	if (CryptExportKey(hKey, hExpKey, SIMPLEBLOB, 0, 0, cbData)){

		if ((pbData = (BYTE *)LocalAlloc(LMEM_FIXED, *cbData))){

			if (CryptExportKey(hKey, hExpKey, SIMPLEBLOB, 0, pbData, cbData)){
				/*
        printf(L"AesKeyExport BLOB 2 = \"");
				for (int i=0; i < (*cbData); i++)
				{
					printf("%02x", pbData[i]);
				}
				printf("\"\n\n");
        */
				pbKeyData = pbData + sizeof(BLOBHEADER) + sizeof(ALG_ID);
				(*cbData) -= (sizeof(BLOBHEADER) + sizeof(ALG_ID));
				bResult = CryptDecrypt(hExpKey, 0, TRUE, 0, pbKeyData, cbData);
			}
			else{
				printf("[-] Error Exporting Simple blob. err: %s\n", GetLastError());
			}
		}
		else{
			printf("[-] Out of memory in export raw key\n");
		}
	}
	else{
		printf("[-] Error in initializing key export. err: %s", GetLastError());

	}

	if (hExpKey) CryptDestroyKey(hExpKey);
	if (!bResult && pbData) LocalFree(pbData);
	else if (pbData) MoveMemory(pbData, pbKeyData, *cbData);
	return (bResult ? (BYTE *)LocalReAlloc(pbData, *cbData, 0) : 0);

}
