#include "CdigitalSig.h"
CdigitalSig::CdigitalSig(LPCWSTR lpFileName)
{
	CheckFileTrust(lpFileName);
}
std::string CdigitalSig::GetDigitalSigString()
{
	return this->DigitalSigString;
}

std::string CdigitalSig::GetMd5DigitalSigString()
{
	return this->Md5DigitalSigString;
}

DWORD CdigitalSig::GetDigitalState()
{
	return this->dDigitalState;
}



LONG CdigitalSig::GetSoftSign(PCWSTR v_pszFilePath, char* v_pszSign, int v_iBufSize)
{
	//首先判断参数是否正确
	if (v_pszFilePath == NULL) return -1;

	HCERTSTORE		  hStore = NULL;
	HCRYPTMSG		  hMsg = NULL;
	PCCERT_CONTEXT    pCertContext = NULL;
	BOOL			  bResult;
	DWORD dwEncoding, dwContentType, dwFormatType;
	PCMSG_SIGNER_INFO pSignerInfo = NULL;
	PCMSG_SIGNER_INFO pCounterSignerInfo = NULL;
	DWORD			  dwSignerInfo;
	CERT_INFO		  CertInfo;
	SYSTEMTIME        st;
	LONG              lRet;
	DWORD             dwDataSize = 0;

	char   chTemp[MAX_PATH] = { 0 };

	do
	{

		//从签名文件中获取存储句柄
		bResult = CryptQueryObject(
			CERT_QUERY_OBJECT_FILE,										//指示要查询的对象的类型
			v_pszFilePath,
			CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
			CERT_QUERY_FORMAT_FLAG_BINARY,
			0,
			&dwEncoding,
			&dwContentType,
			&dwFormatType,
			&hStore,
			&hMsg,
			NULL
		);

		if (!bResult)
		{
			lRet = -1;
			break;
		}
		//获取签名信息所需的缓冲区大小
		bResult = CryptMsgGetParam(
			hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			NULL,
			&dwSignerInfo
		);
		if (!bResult)
		{
			lRet = -1;
			break;
		}

		//分配缓冲区
		pSignerInfo = (PCMSG_SIGNER_INFO)LocalAlloc(LPTR, dwSignerInfo);
		if (pSignerInfo == NULL)
		{
			lRet = -1;
			break;
		}


		//获取签名信息
		bResult = CryptMsgGetParam(
			hMsg,
			CMSG_SIGNER_INFO_PARAM,
			0,
			pSignerInfo,
			&dwSignerInfo
		);
		if (!bResult)
		{
			lRet = -1;
			break;
		}

		CertInfo.Issuer = pSignerInfo->Issuer;
		CertInfo.SerialNumber = pSignerInfo->SerialNumber;

		pCertContext = CertFindCertificateInStore(
			hStore,
			CRYPT_ASN_ENCODING,
			0,
			CERT_FIND_SUBJECT_CERT,
			(PVOID)&CertInfo,
			NULL
		);
		if (pCertContext == NULL)
		{
			lRet = -1;
			break;
		}


		//获取数字键名
		//没有给定缓冲区，那么说明只要获取下需要的长度
		if (v_pszSign == NULL)
		{
			dwDataSize = CertGetNameString(
				pCertContext,
				CERT_NAME_SIMPLE_DISPLAY_TYPE,
				0,
				NULL,
				NULL,
				0
			);
			if (dwDataSize != 0)
			{
				lRet = dwDataSize;
			}
			else
			{
				lRet = -1;
			}

			break;
		}

		if (!(CertGetNameStringA(
			pCertContext,
			CERT_NAME_SIMPLE_DISPLAY_TYPE,
			0,
			NULL,
			v_pszSign,
			v_iBufSize
		)
			)
			)
		{

			lRet = -1;
			break;
		}
		lRet = 0;

	} while (FALSE);

	if (pSignerInfo != NULL)
	{
		LocalFree((HLOCAL)pSignerInfo);
	}
	if (hStore != NULL)
		CertCloseStore(hStore, 0);
	if (hMsg != NULL)
		CryptMsgClose(hMsg);
	if (pCertContext != NULL)
		CertFreeCertificateContext(pCertContext);
	return lRet;
}


void CdigitalSig::CheckFileTrust(LPCWSTR lpFileName)		//两种md5都是md5的ascii
{

	WINTRUST_DATA wd = { 0 };
	WINTRUST_FILE_INFO wfi = { 0 };
	WINTRUST_CATALOG_INFO wci = { 0 };
	CATALOG_INFO ci = { 0 };

	HCATADMIN hCatAdmin = NULL;
	if (!CryptCATAdminAcquireContext(&hCatAdmin, NULL, 0))
	{
		return;
	}

	HANDLE hFile = CreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
		NULL, OPEN_EXISTING, 0, NULL);
	if (INVALID_HANDLE_VALUE == hFile)
	{
		CryptCATAdminReleaseContext(hCatAdmin, 0);
		return;
	}

	DWORD dwCnt = 100;
	BYTE byHash[100];
	CryptCATAdminCalcHashFromFileHandle(hFile, &dwCnt, byHash, 0);
	CloseHandle(hFile);

	LPWSTR pszMemberTag = new WCHAR[dwCnt * 2 + 1];
	for (DWORD dw = 0; dw < dwCnt; ++dw)
	{
		wsprintfW(&pszMemberTag[dw * 2], L"%02X", byHash[dw]);
	}

	HCATINFO hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, byHash, dwCnt, 0, NULL);

	GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
	HRESULT lStatus = WinVerifyTrust(NULL, &action, &wd);
	DWORD dwLastError = GetLastError();
	switch (lStatus)
	{
	case ERROR_SUCCESS:
		/*
		Signed file:
		- Hash that represents the subject is trusted.
		- Trusted publisher without any verification errors.
		- UI was disabled in dwUIChoice. No publisher or
		time stamp chain errors.
		- UI was enabled in dwUIChoice and the user clicked
		"Yes" when asked to install and run the signed
		subject.
		*/
		/*wprintf_s(L"The file \"%s\" is signed and the signature "
			L"was verified.\n",
			pwszSourceFile);*/
		this->dDigitalState = DIGITAL_SIGSTATE_VALID;
		break;

	case TRUST_E_NOSIGNATURE:
		// The file was not signed or had a signature 
		// that was not valid.

		// Get the reason for no signature.

		if (TRUST_E_NOSIGNATURE == dwLastError ||
			TRUST_E_SUBJECT_FORM_UNKNOWN == dwLastError ||
			TRUST_E_PROVIDER_UNKNOWN == dwLastError)
		{
			// The file was not signed.
			/*wprintf_s(L"The file \"%s\" is not signed.\n",
				pwszSourceFile);*/
			this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
		}
		else
		{
			// The signature was not valid or there was an error 
			// opening the file.
			/*wprintf_s(L"An unknown error occurred trying to "
				L"verify the signature of the \"%s\" file.\n",
				pwszSourceFile);*/
			this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
		}

		break;

	case TRUST_E_EXPLICIT_DISTRUST:
		// The hash that represents the subject or the publisher 
		// is not allowed by the admin or user.
		/*wprintf_s(L"The signature is present, but specifically "
			L"disallowed.\n");*/
		this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
		break;

	case TRUST_E_SUBJECT_NOT_TRUSTED:
		// The user clicked "No" when asked to install and run.
		/*wprintf_s(L"The signature is present, but not "
			L"trusted.\n");*/
		this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
		break;

	case CRYPT_E_SECURITY_SETTINGS:
		/*
		The hash that represents the subject or the publisher
		was not explicitly trusted by the admin and the
		admin policy has disabled user trust. No signature,
		publisher or time stamp errors.
		*/
		/*wprintf_s(L"CRYPT_E_SECURITY_SETTINGS - The hash "
			L"representing the subject or the publisher wasn't "
			L"explicitly trusted by the admin and admin policy "
			L"has disabled user trust. No signature, publisher "
			L"or timestamp errors.\n");*/
		this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
		break;

	default:
		// The UI was disabled in dwUIChoice or the admin policy 
		// has disabled user trust. lStatus contains the 
		// publisher or time stamp chain error.
		if (dwLastError == 0x800b0101)	//过期
		{
			this->dDigitalState = DIGITAL_SIGSTATE_EXPIRE;
		}
		else if (dwLastError == 0x800b010c) {	//吊销
			this->dDigitalState = DIGITAL_SIGSTATE_REVOKED;
		}
		else if (dwLastError == 0x80096010) {	//根证书
			this->dDigitalState = DIGITAL_SIGSTATE_VALID;
		}
		else {
			this->dDigitalState = DIGITAL_SIGSTATE_OTHER;
			//wprintf_s(L"Error is: 0x%x.\n",lStatus);
		}

		break;
	}
	if (NULL != hCatInfo)
	{
		CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
	}
	CryptCATAdminReleaseContext(hCatAdmin, 0);

	delete[] pszMemberTag;
	return;
}