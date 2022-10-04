#include "stdafx.h"
#include "CSRpcTransportTools.h"
#include "SmartBlob.h"
#include "windows.h"
#include "NextGenerationCryptoAPIProvider.h"
#include "bcrypt.h"
#include "SmartBlob.h"
#include "CSMessages.h"
#include "ncrypt.h"
#include "OpenSslIncludes.h"
#include "LogTemplateMessages.h"
#include <zlib.h>

#pragma comment (lib, "bcrypt")
#pragma comment (lib, "ncrypt")

#define AES_256_KEY_OBJECT_LENGTH 32
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

#define SHA1_DIGEST_SIZE 20

// Constructor / Destructor
// ----------------

CNextGenerationCryptoAPIProvider::CNextGenerationCryptoAPIProvider()
{
}

CNextGenerationCryptoAPIProvider::~CNextGenerationCryptoAPIProvider()
{
}

void CNextGenerationCryptoAPIProvider::MakeRandomBytes( BYTE* pBytesToFill, long lSizeToFill )
{
	for (long i = 0; i < lSizeToFill; i++)
	{
		pBytesToFill[i] = (BYTE)rand();
	}
}

// Methods
// ----------------

/// <summary> ���������� �� ������ ���� </summary>
BOOL CNextGenerationCryptoAPIProvider::GenerateAES256SessionKey( CString& strGeneratedSessionKey )
{
	SMART_BLOB recRandomKeyBlob;
	recRandomKeyBlob.cbSize = AES_256_KEY_OBJECT_LENGTH;
	recRandomKeyBlob.pBlobData = new BYTE[AES_256_KEY_OBJECT_LENGTH];
	MakeRandomBytes( recRandomKeyBlob.pBlobData, AES_256_KEY_OBJECT_LENGTH );

	HRESULT hResult = S_OK;
	BCRYPT_ALG_HANDLE hAesAlg = NULL;
	BCRYPT_KEY_HANDLE hKey = NULL;
	DWORD cbData = 0;
	DWORD cbKeyObject = 0;

	// ������ �� ����� �� AES ���������
	hResult = BCryptOpenAlgorithmProvider( &hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptOpenAlgorithmProvider()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ����������� ����� �� � ���������� �� ������, �������� �����
	hResult = BCryptGetProperty( hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbData, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptGetProperty()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ��������� �� �����, � ����� �� �������� �������� ����
	SMART_BLOB recSessionKeyBlob;
	recSessionKeyBlob.cbSize = cbKeyObject;
	recSessionKeyBlob.pBlobData = new BYTE[cbKeyObject];

	// ���������� ������ ����
	hResult = BCryptGenerateSymmetricKey( hAesAlg, &hKey, recSessionKeyBlob.pBlobData, recSessionKeyBlob.cbSize
										, recRandomKeyBlob.pBlobData, recRandomKeyBlob.cbSize, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptGenerateSymmetricKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	SMART_BLOB recGeneratedSessionKey;
	// ����������� ����� �� � ������� ������ �� ������� �� �����
	hResult = BCryptExportKey( hKey, NULL, BCRYPT_KEY_DATA_BLOB, NULL, 0, &recGeneratedSessionKey.cbSize, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - BCryptExportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if
	
	// �������� � ������ ������� ����� �� �����
	recGeneratedSessionKey.pBlobData = new BYTE[recGeneratedSessionKey.cbSize];

	// ������ �������� �� ����� � �� ������� �������
	hResult = BCryptExportKey( hKey, NULL, BCRYPT_KEY_DATA_BLOB, recGeneratedSessionKey.pBlobData, recGeneratedSessionKey.cbSize, &recGeneratedSessionKey.cbSize, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - BCryptExportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	if( !EncodeSessionKey( recGeneratedSessionKey, strGeneratedSessionKey ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("EncodeSessionKey()"), _T("") ) );
		return FALSE;
	}//if

	// ������������� ���������� �� ��������� � ����������� ����� ( � ����������� �������� ������������ )
	if(hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg,0);
	}//if

	if (hKey)    
	{
		BCryptDestroyKey(hKey);
	}//if

	return TRUE;
}

/// <summary> ���������� �� ����� ���� ���������� ���� </summary>
BOOL CNextGenerationCryptoAPIProvider::EncryptDataWithSymmetricKey( const CString& strSymmetricKey, RPC_BUF& recRpcBuffer )
{
	DWORD dwOutputBufferSize = 0;
	HRESULT hResult = S_OK;

	SMART_BLOB recSessionKey;
	if( !DecodeSessionKey( strSymmetricKey, recSessionKey ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("DecodeSessionKey()"), _T("") ) );
		return FALSE;
	}//if

	BCRYPT_ALG_HANDLE hAesAlg = NULL;

	// �������� provider-� �� ���������
	hResult = BCryptOpenAlgorithmProvider( &hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptOpenAlgorithmProvider()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	BCRYPT_KEY_HANDLE hKey = NULL;

	// ���������� ������ ���� �� ���������� ����
	hResult = BCryptImportKey( hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL
							 , 0, recSessionKey.pBlobData, recSessionKey.cbSize, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptImportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ������� ������ ������ �� ������
	hResult = BCryptEncrypt(hKey, recRpcBuffer.buf, recRpcBuffer.size, NULL, NULL, 0, NULL, 0, &dwOutputBufferSize, BCRYPT_BLOCK_PADDING );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - BCryptEncrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	DWORD dwData = 0;

	SMART_BLOB recEncryptedBuffer;
	recEncryptedBuffer.cbSize = dwOutputBufferSize;
	recEncryptedBuffer.pBlobData = new BYTE[recEncryptedBuffer.cbSize];

	// ������ ������ ����������
	hResult = BCryptEncrypt(hKey, recRpcBuffer.buf, recRpcBuffer.size, NULL, NULL, 0, recEncryptedBuffer.pBlobData, recEncryptedBuffer.cbSize, &dwData, BCRYPT_BLOCK_PADDING );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - BCryptEncrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	recRpcBuffer.buf = ( BYTE* )realloc( recRpcBuffer.buf , dwData );
	recRpcBuffer.size = dwData;
	memcpy( recRpcBuffer.buf, recEncryptedBuffer.pBlobData, recRpcBuffer.size );

	// ��������� ��������� provider-� � ����������� �����
	if(hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg,0);
	}//if

	if (hKey)    
	{
		BCryptDestroyKey(hKey);
	}//if

	return TRUE;
}

/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
BOOL CNextGenerationCryptoAPIProvider::DecryptDataWithSymmetricKey( CString& strSymmetricKey, RPC_BUF& recRpcBuffer )
{
	DWORD dwOutputBufferSize = 0;
	HRESULT hResult = S_OK;

	SMART_BLOB recSessionKey;
	if( !DecodeSessionKey( strSymmetricKey, recSessionKey ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("DecodeSessionKey()"), _T("") ) );
		return FALSE;
	}//if

	BCRYPT_ALG_HANDLE hAesAlg = NULL;

	// �������� provider-� �� ���������
	hResult = BCryptOpenAlgorithmProvider( &hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptOpenAlgorithmProvider()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	BCRYPT_KEY_HANDLE hKey = NULL;

	// ���������� ������ ���� �� ���������� ����
	hResult = BCryptImportKey( hAesAlg, NULL, BCRYPT_KEY_DATA_BLOB, &hKey, NULL
		, 0, recSessionKey.pBlobData, recSessionKey.cbSize, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptImportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ������� ������ ������ �� ������
	hResult = BCryptDecrypt(hKey, recRpcBuffer.buf, recRpcBuffer.size, NULL, NULL, 0, NULL, 0, &dwOutputBufferSize, BCRYPT_BLOCK_PADDING );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - BCryptDecrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	SMART_BLOB recDecryptedBlob;
	recDecryptedBlob.cbSize = dwOutputBufferSize;
	recDecryptedBlob.pBlobData = new BYTE[ recDecryptedBlob.cbSize ];

	DWORD dwData = 0;

	// ������ ������ ������������
	hResult = BCryptDecrypt(hKey, recRpcBuffer.buf, recRpcBuffer.size, NULL, NULL, 0, recDecryptedBlob.pBlobData, recDecryptedBlob.cbSize, &dwData, BCRYPT_BLOCK_PADDING );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - BCryptDecrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	recRpcBuffer.size = dwData;
	memcpy( recRpcBuffer.buf, recDecryptedBlob.pBlobData, recRpcBuffer.size );

	// ��������� ��������� provider-� � ����������� �����
	if(hAesAlg)
	{
		BCryptCloseAlgorithmProvider(hAesAlg,0);
	}//if

	if (hKey)    
	{
		BCryptDestroyKey(hKey);
	}//if

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::EncryptSymmetricKey( SMART_BLOB& recPublicKeyBlob, CString& recGeneratedSessionKey, SMART_BLOB& recEncryptedSessionKey )
{
	HRESULT hResult = S_OK;
	PBYTE pbPKEY = NULL;
	DWORD dwPublicKeySize = 0;

	if( recPublicKeyBlob.IsEmpty() )
	{
		return FALSE;
	}

	PCCERT_CONTEXT pPublicCertificateContext = CertCreateCertificateContext( X509_ASN_ENCODING | PKCS_7_ASN_ENCODING
																		   , recPublicKeyBlob.pBlobData, recPublicKeyBlob.cbSize );

	if( pPublicCertificateContext == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("pPublicCertificateContext == NULL"), _T("") ) );
		return FALSE;
	}//if

	// ���������� �����, �� �� ����� �� ������ handler ��� ����
	if( !CryptDecodeObjectEx((PKCS_7_ASN_ENCODING | X509_ASN_ENCODING),
							CNG_RSA_PUBLIC_KEY_BLOB,
							pPublicCertificateContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
							pPublicCertificateContext->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
							CRYPT_ENCODE_ALLOC_FLAG,
							NULL,
							&pbPKEY,
							&dwPublicKeySize) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("CryptDecodeObjectEx(..)"), _T("") ) );
		return FALSE;
	}//if

	// ������� handler ��� �����
	BCRYPT_KEY_HANDLE hBCryptKeyHandle = ImportKey( pbPKEY, dwPublicKeySize );
	if( hBCryptKeyHandle == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("hBCryptKeyHandle == NULL"), _T("") ) );
		return FALSE;
	}//if

	DWORD dwOutputBufferSize = 0;

	SMART_BLOB recSessionKey;
	if( !DecodeSessionKey( recGeneratedSessionKey, recSessionKey ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("DecodeSessionKey()"), _T("") ) );
		return FALSE;
	}//if

	// ���������� ����� ��� �� �� ��������� ��������� �� ������
	hResult = BCryptEncrypt( hBCryptKeyHandle, recSessionKey.pBlobData, recSessionKey.cbSize, NULL, NULL, 0
						   , NULL, 0, &dwOutputBufferSize, BCRYPT_PAD_PKCS1 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - BCryptEncrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	recEncryptedSessionKey.cbSize = dwOutputBufferSize;
	recEncryptedSessionKey.pBlobData = new BYTE[recEncryptedSessionKey.cbSize];

	// ������ ������ ����������
	hResult = BCryptEncrypt( hBCryptKeyHandle, recSessionKey.pBlobData, recSessionKey.cbSize, NULL, NULL, 0
						   , recEncryptedSessionKey.pBlobData, recEncryptedSessionKey.cbSize, &dwOutputBufferSize, BCRYPT_PAD_PKCS1 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - BCryptEncrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ��������� ��������� provider-� � ����������� �����
	if (hBCryptKeyHandle)    
	{
		BCryptDestroyKey(hBCryptKeyHandle);
	}//if

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::DecryptSymmetricKey( SMART_BLOB& recEncryptedSessionKey
														  , CString& recDecryptedSessionKey
														  , const CString strCertificateThumbprint )
{
	// ��� �� ��� ���������� ������ ����, ����� ���� �� �������� ���������� ����������
	if( strCertificateThumbprint.IsEmpty() || recEncryptedSessionKey.IsEmpty() )
		return TRUE;

	HRESULT hResult = S_OK;
	long lLastError = 0;
	DWORD dwKeySpec = 0;
	NCRYPT_KEY_HANDLE hKeyHandle = NULL;

	// ������� ����������� �� store-�
	HCERTSTORE hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"My" );

	if( hCertStore == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("hCertStore == NULL"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	PCCERT_CONTEXT pCertContext = GetCertificateByThumbprint( strCertificateThumbprint, hCertStore );

	if( pCertContext == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("pCertContext == NULL"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	// ���������� handler ��� private ������ �� ����������� ( private ������ �� ������ �� �� ������� ������ �� ������� )
	if( !CryptAcquireCertificatePrivateKey( pCertContext, CRYPT_ACQUIRE_ONLY_NCRYPT_KEY_FLAG, NULL, &hKeyHandle, &dwKeySpec, NULL ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("CryptAcquireCertificatePrivateKey()"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	SMART_BLOB recPrivateKey;
	DWORD dwPrivateKeySize = 0;
	long lAllowKeyExportingPlain = NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG;

	// �������� �� handler-�, �� �� ����������� ������� �� �� ������ � plaintext �����
	hResult = NCryptSetProperty( hKeyHandle, NCRYPT_EXPORT_POLICY_PROPERTY, (PBYTE)&lAllowKeyExportingPlain, sizeof(long), NCRYPT_SILENT_FLAG );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("NCryptSetProperty()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ������ ����� ������� �� �� ��������� ��������� �� �����
	hResult = NCryptExportKey( hKeyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, NULL, 0, &dwPrivateKeySize, NCRYPT_SILENT_FLAG );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - NCryptExportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	recPrivateKey.cbSize = dwPrivateKeySize;
	recPrivateKey.pBlobData = new BYTE[ recPrivateKey.cbSize ];

	// ����� �������, �� �� �������� ������
	hResult = NCryptExportKey( hKeyHandle, NULL, BCRYPT_RSAPRIVATE_BLOB, NULL, recPrivateKey.pBlobData, recPrivateKey.cbSize, &dwPrivateKeySize, NCRYPT_SILENT_FLAG );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - NCryptExportKey()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	// ���������� handler �� plain �����
	BCRYPT_KEY_HANDLE recPrivateKeyHandle = ImportKey( recPrivateKey.pBlobData, recPrivateKey.cbSize );
	if( recPrivateKeyHandle == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("recPrivateKeyHandle == NULL"), _T("") ) );
		return FALSE;
	}//if

	DWORD dwOutputBufferSize = 0;

	// ������� ������ ������ �� ������
	hResult = BCryptDecrypt( recPrivateKeyHandle, recEncryptedSessionKey.pBlobData, recEncryptedSessionKey.cbSize
						   , NULL, NULL, 0, NULL, 0, &dwOutputBufferSize, BCRYPT_PAD_PKCS1 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("First - BCryptDecrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	SMART_BLOB recDecryptedBlob;
	recDecryptedBlob.cbSize = dwOutputBufferSize;
	recDecryptedBlob.pBlobData = new BYTE[ recDecryptedBlob.cbSize ];

	DWORD dwData = 0;

	// ������ ������ ������������
	hResult = BCryptDecrypt( recPrivateKeyHandle, recEncryptedSessionKey.pBlobData, recEncryptedSessionKey.cbSize
						   , NULL, NULL, 0, recDecryptedBlob.pBlobData, recDecryptedBlob.cbSize, &dwData, BCRYPT_PAD_PKCS1 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Second - BCryptDecrypt()"), GetErrorMessage(hResult) ) );
		return FALSE;
	}//if

	SMART_BLOB recDecryptedSessionKeyBlob;
	recDecryptedSessionKeyBlob.cbSize = recDecryptedBlob.cbSize;
	recDecryptedSessionKeyBlob.pBlobData = new BYTE[recDecryptedSessionKeyBlob.cbSize];
	memcpy( recDecryptedSessionKeyBlob.pBlobData, recDecryptedBlob.pBlobData, recDecryptedSessionKeyBlob.cbSize );

	if( !EncodeSessionKey( recDecryptedSessionKeyBlob, recDecryptedSessionKey ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("EncodeSessionKey()"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	if( hKeyHandle )
	{
		NCryptDeleteKey( hKeyHandle, NCRYPT_SILENT_FLAG );
	}//if

	if( !CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("CertCloseStore()"), CToStr::Parse( GetLastError() ) ) );
		return NULL;
	}//if

	if( recPrivateKeyHandle )
	{
		BCryptDestroyKey( recPrivateKeyHandle );
	}//if

	return TRUE;
}

BCRYPT_KEY_HANDLE CNextGenerationCryptoAPIProvider::ImportKey( BYTE* pPublicKeyData, ULONG ulPublicKeyLength )
{
	HRESULT hResult = S_FALSE;
	long lLastError = 0;

	if( ulPublicKeyLength < sizeof(BCRYPT_KEY_BLOB) )
	{
		return NULL;
	}//if

	const wchar_t* wszAlgorithm;
	bool bIsPublicKey = false;

	// �������� ����� � ���� �� ����� � ���� � �������� ������ Magic ������� �� ������ ��
	switch( reinterpret_cast<BCRYPT_KEY_BLOB*>( pPublicKeyData )->Magic )
	{
		case BCRYPT_RSAPUBLIC_MAGIC:
		case BCRYPT_RSAPRIVATE_MAGIC:
		case BCRYPT_RSAFULLPRIVATE_MAGIC:
		{
			if(ulPublicKeyLength < sizeof(BCRYPT_RSAKEY_BLOB))
			{
				return NULL;
			}//if

			wszAlgorithm = BCRYPT_RSA_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_RSAPUBLIC_MAGIC);
			break;
		}//case
		
		case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
		case BCRYPT_ECDH_PRIVATE_P256_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDH_P256_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDH_PUBLIC_P256_MAGIC);
			break;
		}//case
		
		case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
		case BCRYPT_ECDH_PRIVATE_P384_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDH_P384_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDH_PUBLIC_P384_MAGIC);
			break;
		}//case
		case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
		case BCRYPT_ECDH_PRIVATE_P521_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDH_P521_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDH_PUBLIC_P521_MAGIC);
			break;
		}//case
			
		case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDSA_P256_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDSA_PUBLIC_P256_MAGIC);
			break;
		}//case
		
		case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDSA_P384_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDSA_PUBLIC_P384_MAGIC);
			break;
		}//case
		
		case BCRYPT_ECDSA_PUBLIC_P521_MAGIC:
		case BCRYPT_ECDSA_PRIVATE_P521_MAGIC:
		{
			wszAlgorithm = BCRYPT_ECDSA_P521_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_ECDSA_PUBLIC_P521_MAGIC);
			break;
		}//case

		case BCRYPT_DH_PUBLIC_MAGIC:
		case BCRYPT_DH_PRIVATE_MAGIC:
		{
			if(ulPublicKeyLength < sizeof(BCRYPT_DH_KEY_BLOB))
			{
				return NULL;
			}//if

			wszAlgorithm = BCRYPT_DH_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_DH_PUBLIC_MAGIC);
			break;
		}//case
		
		case BCRYPT_DSA_PUBLIC_MAGIC:
		case BCRYPT_DSA_PRIVATE_MAGIC:
		{
			if(ulPublicKeyLength < sizeof(BCRYPT_DSA_KEY_BLOB))
			{
				return NULL;
			}//if

			wszAlgorithm = BCRYPT_DSA_ALGORITHM;
			bIsPublicKey = (reinterpret_cast<BCRYPT_KEY_BLOB*>(pPublicKeyData)->Magic == BCRYPT_DSA_PUBLIC_MAGIC);
			break;
		}//case

		default:
		{
			return NULL;
		}//default

	}//switch

	BCRYPT_ALG_HANDLE hAlgorithm;

	// �������� ��������� ������ ���� �� �����
	hResult = BCryptOpenAlgorithmProvider( &hAlgorithm, wszAlgorithm, MS_PRIMITIVE_PROVIDER, 0 );
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptOpenAlgorithmProvider()"), GetErrorMessage(hResult) ) );
		return NULL;
	}//if

	// ����������� �����, �� �� ������ handle ��� ����
	BCRYPT_KEY_HANDLE hKey;
	hResult = BCryptImportKeyPair(hAlgorithm, NULL, bIsPublicKey ? BCRYPT_PUBLIC_KEY_BLOB : BCRYPT_PRIVATE_KEY_BLOB, &hKey, pPublicKeyData, ulPublicKeyLength, 0);
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptImportKeyPair()"), GetErrorMessage(hResult) ) );
		return NULL;
	}//if

	// ��������� provider-�
	hResult = BCryptCloseAlgorithmProvider(hAlgorithm, 0);
	if( hResult != S_OK )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptCloseAlgorithmProvider()"), GetErrorMessage(hResult) ) );
		return NULL;
	}//if

	return hKey;
}

BOOL CNextGenerationCryptoAPIProvider::GetCertificatePublicPart( const CString strCertificateThumbprint, SMART_BLOB& recPublicCertificateContext )
{
	HCERTSTORE hCertStore = CertOpenStore( CERT_STORE_PROV_SYSTEM, 0, NULL, CERT_SYSTEM_STORE_CURRENT_USER, L"My" );

	if( hCertStore == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("hCertStore == NULL"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	PCCERT_CONTEXT pCertContext = GetCertificateByThumbprint( strCertificateThumbprint, hCertStore );

	if( pCertContext == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("pCertContext == NULL"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	recPublicCertificateContext.cbSize = pCertContext->cbCertEncoded;
	recPublicCertificateContext.pBlobData = new BYTE[ recPublicCertificateContext.cbSize ];
	memcpy( recPublicCertificateContext.pBlobData, pCertContext->pbCertEncoded, recPublicCertificateContext.cbSize );

	if( !CertCloseStore( hCertStore, CERT_CLOSE_STORE_FORCE_FLAG ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("CertCloseStore()"), CToStr::Parse( GetLastError() ) ) );
		return FALSE;
	}//if

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::GetHMACSHA256(const CStringA strKey, const CStringA strValue, OUT CString& strHMAC)
{
	strHMAC = _T("");

	HRESULT hResult = S_OK;
	BCRYPT_ALG_HANDLE hAlgProvider;
	hResult = BCryptOpenAlgorithmProvider(&hAlgProvider, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (hResult != S_OK)
	{
		CSMsg::Log(LOG_ERROR_CALLING(_T("BCryptOpenAlgorithmProvider"), GetErrorMessage(hResult)));
		return FALSE;
	}

	// ������� �� digest-�
	CS_CRYPT_BLOB oBlob;
	DWORD dwResultLength = 0;
	hResult = BCryptGetProperty(hAlgProvider, BCRYPT_HASH_LENGTH, (PBYTE)&oBlob.cbSize, sizeof(oBlob.cbSize), &dwResultLength, 0);
	if (hResult != S_OK)
	{
		// ������������� �� ����������
		if (NULL != hAlgProvider)
			BCryptCloseAlgorithmProvider(hAlgProvider, 0);

		CSMsg::Log(LOG_ERROR_CALLING(_T("BCryptGetProperty"), GetErrorMessage(hResult)));
		return FALSE;
	}

	// �������� �� ����� �� digest-�
	oBlob.pBlobData = new BYTE[oBlob.cbSize];
	SecureZeroMemory(oBlob.pBlobData, oBlob.cbSize);

	// ���� �� ����������
	CS_CRYPT_BLOB oBlobKey(strKey);
	DWORD dwKeySizeWithoutNullTerminator = oBlobKey.cbSize - 1;

	// ����� �� ������ �� hash/hmac
	// NULL ���� ����� ��������� ��������, �� ���������� �� �� ����� �� ������� �� ������ 
	BCRYPT_HASH_HANDLE hHash = NULL;
	hResult = BCryptCreateHash(hAlgProvider, &hHash, NULL, 0, oBlobKey.pBlobData, dwKeySizeWithoutNullTerminator, 0);
	if (hResult != S_OK)
	{
		// ������������� �� ����������
		if (NULL != hAlgProvider)
			BCryptCloseAlgorithmProvider(hAlgProvider, 0);

		CSMsg::Log(LOG_ERROR_CALLING(_T("BCryptCreateHash"), GetErrorMessage(hResult)));
		return FALSE;
	}

	// �������� �� ��������
	CS_CRYPT_BLOB oBlobValue(strValue);
	DWORD dwValueSizeWithoutNullTerminator = oBlobValue.cbSize - 1;

	// ������ ��������
	hResult = BCryptHashData(hHash, oBlobValue.pBlobData, dwValueSizeWithoutNullTerminator, 0);
	if (hResult != S_OK)
	{
		// ����������� �� ������ �� ��������, ��� �� � ���������
		if (NULL != hHash)
			BCryptDestroyHash(hHash);

		// ������������� �� ����������
		if (NULL != hAlgProvider)
			BCryptCloseAlgorithmProvider(hAlgProvider, 0);

		CSMsg::Log(LOG_ERROR_CALLING(_T("BCryptHashData"), GetErrorMessage(hResult)));
		return FALSE;
	}

	// ������������� �� ������ �� �������� � ��������� �� ���������
	hResult = BCryptFinishHash(hHash, oBlob.pBlobData, oBlob.cbSize, 0);
	if (hResult != S_OK)
	{
		// ����������� �� ������ �� ��������, ��� �� � ���������
		if (NULL != hHash)
			BCryptDestroyHash(hHash);

		// ������������� �� ����������
		if (NULL != hAlgProvider)
			BCryptCloseAlgorithmProvider(hAlgProvider, 0);

		CSMsg::Log(LOG_ERROR_CALLING(_T("BCryptFinishHash"), GetErrorMessage(hResult)));
		return FALSE;
	}

	// ����������� �� ������ �� ��������, ��� �� � ���������
	if (NULL != hHash)
		BCryptDestroyHash(hHash);

	// ������������� �� ����������
	if (NULL != hAlgProvider)
		BCryptCloseAlgorithmProvider(hAlgProvider, 0);

	// ������� ��� ��� � �������������� �����
	if (!oBlob.Unpack())
	{
		CSMsg::Log(LOG_ERROR_CALLING(_T("oBlob.Unpack()"), _T("")));
		return FALSE;
	}

	// ANSI ��� ��� TCHAR
	strHMAC = CA2T((LPCSTR)oBlob.pBlobData);

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::GetCRC32(const CStringA strData, CString& strCRC32HexadecimalValue)
{
	SYS_TRY
	{
		uLong ulCRC32 = crc32(0L, Z_NULL, 0);
		ulCRC32 = crc32(ulCRC32, (PBYTE)(LPCSTR)strData, strData.GetLength() * sizeof(char));

		strCRC32HexadecimalValue.Format( _T("%x"), ulCRC32 );
	}

	SYS_CATCH(__FUNCTION__)
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("crc32()"), strData ) );		
		return FALSE;
	}

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::EncodeSessionKey( SMART_BLOB recSessionKeyBlob, CString& strEncodedSessionKey )
{
	int nBase64EncodingSize = Base64EncodeGetRequiredLength( recSessionKeyBlob.cbSize ) + 1;

	char* szBase64Encode = NULL;

	try
	{
		szBase64Encode = new char[ nBase64EncodingSize ];
		memset( szBase64Encode, 0x00, nBase64EncodingSize );
	}// try

	catch( ... )
	{
		delete[] szBase64Encode;
		szBase64Encode = NULL;
		return FALSE;
	}//catch

	// Encode-����
	if( !Base64Encode( recSessionKeyBlob.pBlobData, recSessionKeyBlob.cbSize, szBase64Encode, ( int* )&nBase64EncodingSize, 0 ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("BCryptExportKey(Key) - ��������� ������� �� ����"), _T("") ) );

		delete[] szBase64Encode;
		szBase64Encode = NULL;

		return FALSE;
	}//if

	// ������� �� ���������� ������
	strEncodedSessionKey = szBase64Encode;

	delete[] szBase64Encode;
	szBase64Encode = NULL;

	return TRUE;
}

BOOL CNextGenerationCryptoAPIProvider::DecodeSessionKey( const CString& recEncodedSessionKey, SMART_BLOB& strDecodedSessionKeyBlob )
{
	int nDecodeSize = Base64DecodeGetRequiredLength( (int)_tcslen( recEncodedSessionKey ) ) + 1;
	CStringA strEncrBase64A = CT2A(recEncodedSessionKey);

	strDecodedSessionKeyBlob.cbSize = nDecodeSize;
	strDecodedSessionKeyBlob.pBlobData = new BYTE[nDecodeSize];

	if( !Base64Decode( strEncrBase64A, strEncrBase64A.GetLength(), strDecodedSessionKeyBlob.pBlobData, ( int* )&strDecodedSessionKeyBlob.cbSize ) )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("Base64Decode()"), _T("") ) );
		return FALSE;
	}//if

	return TRUE;
}

CString CNextGenerationCryptoAPIProvider::GetErrorMessage(HRESULT hResult)
{
	CString strErrorMessage = _T("");
	DWORD dwWin32ErrorCode = GetLastError();
	if( dwWin32ErrorCode != 0 )
	{
		strErrorMessage = SystemErrorMessage();
	}//if

	else
	{
		strErrorMessage = _com_error(hResult).ErrorMessage();
	}//else

	return strErrorMessage;
}

PCCERT_CONTEXT CNextGenerationCryptoAPIProvider::GetCertificateByThumbprint( const CString& strCertificateThumbprint, const HCERTSTORE& hStoreHandle )
{
	if( hStoreHandle == NULL )
	{
		CSMsg::Log( LOG_ERROR_CALLING( _T("hCertStore == NULL"), CToStr::Parse( GetLastError() ) ) );
		return NULL;
	}//if

	PCCERT_CONTEXT pCertContext = NULL;
	CS_CRYPT_BLOB recThumbprintBlob;
	recThumbprintBlob.cbSize = SHA1_DIGEST_SIZE;
	recThumbprintBlob.pBlobData = new BYTE[ SHA1_DIGEST_SIZE ];

	DWORD dwPropertySize = 0;
	while( pCertContext = CertEnumCertificatesInStore( hStoreHandle, pCertContext) )
	{
		if( !CertGetCertificateContextProperty( pCertContext, CERT_HASH_PROP_ID, recThumbprintBlob.pBlobData, &recThumbprintBlob.cbSize ) )
		{
			CSMsg::Log( LOG_ERROR_CALLING( _T("CertGetCertificateContextProperty"), CToStr::Parse( GetLastError() ) ) );
			return NULL;
		}

		if( !recThumbprintBlob.Unpack() )
		{
			CSMsg::Log( LOG_ERROR_CALLING( _T("recThumbprintBlob.Unpack"), CToStr::Parse( GetLastError() ) ) );
			return NULL;
		}

		CString strHash = CA2T(( LPCSTR )recThumbprintBlob.pBlobData);

		if( strCertificateThumbprint.CompareNoCase( strHash ) == 0 )
			break;

	}// while

	return pCertContext;
}

// Overrides
// ----------------
