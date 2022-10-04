#pragma once

// Клас за криптиране на RPC комуникацията
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

	/// <summary> Генерира AES 256 сесиен ключ </summary>
	/// <param name="recGeneratedSessionKey"> Генерираният ключ </param>
	BOOL GenerateAES256SessionKey( CString& strGeneratedSessionKey );

	/// <summary> Криптиране на данни чрез симетричен ключ </summary>
	/// <param name="recSymmetricKey"> Подаден блоб, съдържащ симетричен ключ </param>
	/// <param name="recRpcBuffer"> Буфер, който ще криптираме </param>
	BOOL EncryptDataWithSymmetricKey( const CString& strSymmetricKey, RPC_BUF& recRpcBuffer );

	/// <summary> Декриптиране на данни чрез симетричен ключ </summary>
	/// <param name="recSymmetricKeyBlob"> Подаден блоб, съдържащ симетричен ключ </param>
	/// <param name="recRpcBuffer"> Буфер, който ще декриптираме </param>
	BOOL DecryptDataWithSymmetricKey( CString& strSymmetricKey, RPC_BUF& recRpcBuffer );

	/// <summary> Декриптиране на данни чрез симетричен ключ </summary>
	/// <param name="recGeneratedSessionKey"> Генерираният сесиен ключ </param>
	/// <param name="recEncryptedSessionKey"> Криптиран ключ </param>
	BOOL EncryptSymmetricKey( SMART_BLOB& recPublicKeyBlob, CString& recGeneratedSessionKey, SMART_BLOB& recEncryptedSessionKey );
	
	/// <summary> Декриптиране на данни чрез симетричен ключ </summary>
	/// <param name="recEncryptedSessionKey"> Криптиран ключ </param>
	/// <param name="recDecryptedSessionKey"> Декриптиран ключ </param>
	BOOL DecryptSymmetricKey( SMART_BLOB& recEncryptedSessionKey, CString& recDecryptedSessionKey, const CString strCertificateThumbprint );

	/// <summary> Връща публичната част на сертификат </summary>
	/// <param name="strCertificateThumbprint"> Thumbprint на сертификат </param>
	/// <param name="pPublicCertificateContext"> Публичен ключ на сертификата </param>
	BOOL GetCertificatePublicPart( const CString strCertificateThumbprint, SMART_BLOB& recPublicCertificateContext );

	/// <summary> Метод за хеширане HMAC-SHA256 </summary>
	/// <param=strKey> Ключ за подписване </param>
	/// <param=strValue> Стойност за подписване </param>
	/// <param=strHMAC> Изходен параметър - digest на стойността </param>
	/// <returns> Връща true при успех и false при грешка </returns>
	BOOL GetHMACSHA256(const CStringA strKey, const CStringA strValue, OUT CString& strHMAC);

	/// <summary> Метод за генериране на CRC32 </summary>
	/// <param=strData> Входящи данни за калкулиране на CRC32</param>
	/// <param=strCRC32HexadecimalValue> Изходен параметър - CRC32 на стойността </param>
	/// <returns> Връща true при успех и false при грешка </returns>
	BOOL GetCRC32( const CStringA strData, CString& strCRC32HexadecimalValue );

private:

	/// <summary> Декриптиране на данни чрез симетричен ключ </summary>
	/// <param name="pBytesToFill"> Буфер, който запълваме </param>
	/// <param name="lSizeToFill"> Размер, който запълваме </param>
	void MakeRandomBytes( BYTE* pBytesToFill, long lSizeToFill );

	///<summary> Връща съобщение за възникналата грешка. </summary>
	CString GetErrorMessage( HRESULT hResult );

	/// <summary> Декриптиране на данни чрез симетричен ключ </summary>
	/// <param name="pPublicKeyData"> Публичен ключ </param>
	/// <param name="ulPublicKeyLength"> Дължина на публичен ключ </param>
	BCRYPT_KEY_HANDLE ImportKey( BYTE* pPublicKeyData, ULONG ulPublicKeyLength );

	/// <summary> Base64 ДЕкодиране на сесиен ключ </summary>
	/// <param name="recEncodedSessionKey"> Кодиран сесиен ключ </param>
	/// <param name="strDecodedSessionKeyBlob"> Декодиран сесиен ключ </param>
	BOOL DecodeSessionKey( const CString& recEncodedSessionKey, SMART_BLOB& strDecodedSessionKeyBlob );

	/// <summary> Base64 кодиране на сесиен ключ </summary>
	/// <param name="recSessionKeyBlob"> Сесиен ключ </param>
	/// <param name="strEncodedSessionKey"> Кодиран сесиен ключ </param>
	BOOL EncodeSessionKey( SMART_BLOB recSessionKeyBlob, CString& strEncodedSessionKey );

	/// <summary> Връща сертификат по подаден thumbprint </summary>
	/// <param name="recSessionKeyBlob"> Сесиен ключ </param>
	/// <param name="strEncodedSessionKey"> Кодиран сесиен ключ </param>
	PCCERT_CONTEXT GetCertificateByThumbprint( const CString& strCertificateThumbprint, const HCERTSTORE& hStoreHandle );

	// Overrides
	// ----------------


	// Members
	// ----------------


	// MFC Macros
	// ----------------
};

