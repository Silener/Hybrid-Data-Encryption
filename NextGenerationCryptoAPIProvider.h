#pragma once

// ���� �� ���������� �� RPC �������������
class CSSYSCOREEXP CNextGenerationCryptoAPIProvider
{
	// Constants
	// ----------------


	// Constructor / Destructor
	// ----------------
public:
	CNextGenerationCryptoAPIProvider();
	virtual ~CNextGenerationCryptoAPIProvider();

	// Methods
	// ----------------
public:

	/// <summary> �������� AES 256 ������ ���� </summary>
	/// <param name="recGeneratedSessionKey"> ������������ ���� </param>
	BOOL GenerateAES256SessionKey( CString& strGeneratedSessionKey );

	/// <summary> ���������� �� ����� ���� ���������� ���� </summary>
	/// <param name="recSymmetricKey"> ������� ����, �������� ���������� ���� </param>
	/// <param name="recRpcBuffer"> �����, ����� �� ���������� </param>
	BOOL EncryptDataWithSymmetricKey( const CString& strSymmetricKey, RPC_BUF& recRpcBuffer );

	/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
	/// <param name="recSymmetricKeyBlob"> ������� ����, �������� ���������� ���� </param>
	/// <param name="recRpcBuffer"> �����, ����� �� ������������ </param>
	BOOL DecryptDataWithSymmetricKey( CString& strSymmetricKey, RPC_BUF& recRpcBuffer );

	/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
	/// <param name="recGeneratedSessionKey"> ������������ ������ ���� </param>
	/// <param name="recEncryptedSessionKey"> ��������� ���� </param>
	BOOL EncryptSymmetricKey( SMART_BLOB& recPublicKeyBlob, CString& recGeneratedSessionKey, SMART_BLOB& recEncryptedSessionKey );
	
	/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
	/// <param name="recEncryptedSessionKey"> ��������� ���� </param>
	/// <param name="recDecryptedSessionKey"> ����������� ���� </param>
	BOOL DecryptSymmetricKey( SMART_BLOB& recEncryptedSessionKey, CString& recDecryptedSessionKey, const CString strCertificateThumbprint );

	/// <summary> ����� ���������� ���� �� ���������� </summary>
	/// <param name="strCertificateThumbprint"> Thumbprint �� ���������� </param>
	/// <param name="pPublicCertificateContext"> �������� ���� �� ����������� </param>
	BOOL GetCertificatePublicPart( const CString strCertificateThumbprint, SMART_BLOB& recPublicCertificateContext );

	/// <summary> ����� �� �������� HMAC-SHA256 </summary>
	/// <param=strKey> ���� �� ���������� </param>
	/// <param=strValue> �������� �� ���������� </param>
	/// <param=strHMAC> ������� ��������� - digest �� ���������� </param>
	/// <returns> ����� true ��� ����� � false ��� ������ </returns>
	BOOL GetHMACSHA256(const CStringA strKey, const CStringA strValue, OUT CString& strHMAC);

	/// <summary> ����� �� ���������� �� CRC32 </summary>
	/// <param=strData> ������� ����� �� ����������� �� CRC32</param>
	/// <param=strCRC32HexadecimalValue> ������� ��������� - CRC32 �� ���������� </param>
	/// <returns> ����� true ��� ����� � false ��� ������ </returns>
	BOOL GetCRC32( const CStringA strData, CString& strCRC32HexadecimalValue );

private:

	/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
	/// <param name="pBytesToFill"> �����, ����� ��������� </param>
	/// <param name="lSizeToFill"> ������, ����� ��������� </param>
	void MakeRandomBytes( BYTE* pBytesToFill, long lSizeToFill );

	///<summary> ����� ��������� �� ������������ ������. </summary>
	CString GetErrorMessage( HRESULT hResult );

	/// <summary> ������������ �� ����� ���� ���������� ���� </summary>
	/// <param name="pPublicKeyData"> �������� ���� </param>
	/// <param name="ulPublicKeyLength"> ������� �� �������� ���� </param>
	BCRYPT_KEY_HANDLE ImportKey( BYTE* pPublicKeyData, ULONG ulPublicKeyLength );

	/// <summary> Base64 ���������� �� ������ ���� </summary>
	/// <param name="recEncodedSessionKey"> ������� ������ ���� </param>
	/// <param name="strDecodedSessionKeyBlob"> ��������� ������ ���� </param>
	BOOL DecodeSessionKey( const CString& recEncodedSessionKey, SMART_BLOB& strDecodedSessionKeyBlob );

	/// <summary> Base64 �������� �� ������ ���� </summary>
	/// <param name="recSessionKeyBlob"> ������ ���� </param>
	/// <param name="strEncodedSessionKey"> ������� ������ ���� </param>
	BOOL EncodeSessionKey( SMART_BLOB recSessionKeyBlob, CString& strEncodedSessionKey );

	/// <summary> ����� ���������� �� ������� thumbprint </summary>
	/// <param name="recSessionKeyBlob"> ������ ���� </param>
	/// <param name="strEncodedSessionKey"> ������� ������ ���� </param>
	PCCERT_CONTEXT GetCertificateByThumbprint( const CString& strCertificateThumbprint, const HCERTSTORE& hStoreHandle );

	// Overrides
	// ----------------


	// Members
	// ----------------


	// MFC Macros
	// ----------------
};

