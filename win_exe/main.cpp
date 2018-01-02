#pragma comment(lib, "crypt32.lib")
#include <stdio.h>
#include "crypto_helper.h"
void main()
{
	printf("[+] Starting Crypto Test\n");
	CryptoHelper  cryptoHlpr;
	BYTE          *pbPublicKey = NULL, *pbPrivateKey = NULL, *pbAesKey = NULL;
	DWORD         dwPublicKeySize = 0,dwPrivateKeySize = 0, dwAesKeySize = 0;
	HRESULT       hr = S_OK;
	HCRYPTKEY		hAes;
	// Get the key container context.
	if (FAILED(hr = cryptoHlpr.AcquireContext(("TestContainer"))))
	{
		printf("[-] Failed AcquireContext\n");
		// Call FormatMessage to display the error returned in hr.
		return;
	}
	// Generate the public/private key pair.
	if (FAILED(hr = cryptoHlpr.GenerateKeyPair()))
	{
		printf("[-] Failed to GenerateKeyPair\n");
		// Call FormatMessage to display the error returned in hr.
		return;
	}
	// Export out the public key blob.
	if (FAILED(hr = cryptoHlpr.ExportPublicKey(&pbPublicKey, dwPublicKeySize)))
	{
		// Call FormatMessage to display the error returned in hr.
		printf("[-] Failed to ExportPublicKey\n");
		return;
	}
	// Print out the public key to console as a
	// hexadecimal string.
	wprintf(L"\n\nPublicKey = \"");
	for (DWORD i=0; i < dwPublicKeySize; i++)
	{
		wprintf(L"%02x",pbPublicKey[i]);
	}
	wprintf(L"\"\n");
	// Export out the private key blob.
	cryptoHlpr.ExportPrivateKey(&pbPrivateKey, dwPrivateKeySize);
	// Print out the private key to console as a
	// hexadecimal string.
	wprintf(L"\nPrivateKey = \"");
	for (int i=0; i < dwPrivateKeySize; i++)
	{
		wprintf(L"%02x",pbPrivateKey[i]);
	}
	wprintf(L"\"\n\n");

	hAes = cryptoHlpr.GenerateAESKey(pbPublicKey, dwPublicKeySize, &pbAesKey, dwAesKeySize, pbPrivateKey, dwPrivateKeySize);

	cryptoHlpr.AESEncryptFile(hAes, Infile, OutFile);

	// Delete the public key blob allocated by the
	// ExportPublicKey method.
	if (pbPublicKey)
		delete [] pbPublicKey;
	// Delete the private key blob allocated by the
	// ExportPrivateKey method.
	if (pbPrivateKey)
		delete [] pbPrivateKey;
	return;
}
