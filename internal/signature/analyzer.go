package signature

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modWintrust = windows.NewLazySystemDLL("wintrust.dll")
	modCrypt32  = windows.NewLazySystemDLL("crypt32.dll")

	procWinVerifyTrust                = modWintrust.NewProc("WinVerifyTrust")
	procCryptQueryObject              = modCrypt32.NewProc("CryptQueryObject")
	procCertGetNameStringW            = modCrypt32.NewProc("CertGetNameStringW")
	procCertFreeCertificateContext    = modCrypt32.NewProc("CertFreeCertificateContext")
	procCryptMsgClose                 = modCrypt32.NewProc("CryptMsgClose")
	procCertCloseStore                = modCrypt32.NewProc("CertCloseStore")
	procCryptMsgGetParam              = modCrypt32.NewProc("CryptMsgGetParam")

	modVersion                   = windows.NewLazySystemDLL("version.dll")
	procGetFileVersionInfoSizeW  = modVersion.NewProc("GetFileVersionInfoSizeW")
	procGetFileVersionInfoW      = modVersion.NewProc("GetFileVersionInfoW")
	procVerQueryValueW           = modVersion.NewProc("VerQueryValueW")
)

// SignatureInfo holds digital signature and version info for a file.
type SignatureInfo struct {
	Signed       bool
	SignValid    bool
	Signer       string
	Company      string
	Product      string
	OriginalName string
	FileVersion  string
}

const (
	TRUST_E_NOSIGNATURE       int32 = -2146762496 // 0x800B0100
	TRUST_E_SUBJECT_NOT_TRUSTED int32 = -2146762748 // 0x800B0004
	TRUST_E_PROVIDER_UNKNOWN  int32 = -2146762751 // 0x800B0001
	TRUST_E_EXPLICIT_DISTRUST int32 = -2146762479 // 0x800B0111
)

// Analyze checks the digital signature and version info of the given file.
func Analyze(path string) *SignatureInfo {
	if path == "" {
		return &SignatureInfo{}
	}

	info := &SignatureInfo{}
	checkSignature(path, info)
	getVersionInfo(path, info)
	return info
}

func checkSignature(path string, info *SignatureInfo) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}

	// WINTRUST_FILE_INFO
	type wintrustFileInfo struct {
		cbStruct       uint32
		pcwszFilePath  *uint16
		hFile          windows.Handle
		pgKnownSubject *windows.GUID
	}

	fileInfo := wintrustFileInfo{
		cbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		pcwszFilePath: pathPtr,
	}

	// WTD_CHOICE_FILE = 1, WTD_STATEACTION_VERIFY = 1, WTD_UI_NONE = 2
	// WINTRUST_ACTION_GENERIC_VERIFY_V2
	actionGUID := windows.GUID{
		Data1: 0xaac56b,
		Data2: 0xcd44,
		Data3: 0x11d0,
		Data4: [8]byte{0x8c, 0xc2, 0x00, 0xc0, 0x4f, 0xc2, 0x95, 0xee},
	}

	type wintrustData struct {
		cbStruct            uint32
		pPolicyCallbackData uintptr
		pSIPClientData      uintptr
		dwUIChoice          uint32
		fdwRevocationChecks uint32
		dwUnionChoice       uint32
		pUnion              uintptr
		dwStateAction       uint32
		hWVTStateData       windows.Handle
		pwszURLReference    *uint16
		dwProvFlags         uint32
		dwUIContext         uint32
		pSignatureSettings  uintptr
	}

	wtd := wintrustData{
		cbStruct:      uint32(unsafe.Sizeof(wintrustData{})),
		dwUIChoice:    2, // WTD_UI_NONE
		dwUnionChoice: 1, // WTD_CHOICE_FILE
		pUnion:        uintptr(unsafe.Pointer(&fileInfo)),
		dwStateAction: 1, // WTD_STATEACTION_VERIFY
		dwProvFlags:   0x00000010, // WTD_CACHE_ONLY_URL_RETRIEVAL - skip online checks
	}

	ret, _, _ := procWinVerifyTrust.Call(
		^uintptr(0), // INVALID_HANDLE_VALUE
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	hr := int32(ret)
	if hr == 0 {
		info.Signed = true
		info.SignValid = true
	} else if hr != TRUST_E_NOSIGNATURE && hr != TRUST_E_PROVIDER_UNKNOWN {
		info.Signed = true
		info.SignValid = false
	}

	// Close state
	wtd.dwStateAction = 2 // WTD_STATEACTION_CLOSE
	procWinVerifyTrust.Call(
		^uintptr(0),
		uintptr(unsafe.Pointer(&actionGUID)),
		uintptr(unsafe.Pointer(&wtd)),
	)

	// Get signer name
	if info.Signed {
		info.Signer = getSignerName(path)
	}
}

func getSignerName(path string) string {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}

	const (
		CERT_QUERY_OBJECT_FILE                = 1
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED = 0x00000400
		CERT_QUERY_FORMAT_FLAG_BINARY         = 0x00000002
		CMSG_SIGNER_INFO_PARAM                = 6
		CERT_INFO_SUBJECT_FLAG                = 7
		CERT_NAME_SIMPLE_DISPLAY_TYPE         = 4
	)

	var certStore windows.Handle
	var cryptMsg windows.Handle
	var encoding uint32

	r, _, _ := procCryptQueryObject.Call(
		CERT_QUERY_OBJECT_FILE,
		uintptr(unsafe.Pointer(pathPtr)),
		CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
		CERT_QUERY_FORMAT_FLAG_BINARY,
		0,
		uintptr(unsafe.Pointer(&encoding)),
		0,
		0,
		uintptr(unsafe.Pointer(&certStore)),
		uintptr(unsafe.Pointer(&cryptMsg)),
		0,
	)
	if r == 0 {
		return ""
	}
	defer procCryptMsgClose.Call(uintptr(cryptMsg))
	defer procCertCloseStore.Call(uintptr(certStore), 0)

	// Get signer info size
	var signerInfoSize uint32
	r, _, _ = procCryptMsgGetParam.Call(
		uintptr(cryptMsg),
		CMSG_SIGNER_INFO_PARAM,
		0,
		0,
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if r == 0 || signerInfoSize == 0 {
		return ""
	}

	signerInfoBuf := make([]byte, signerInfoSize)
	r, _, _ = procCryptMsgGetParam.Call(
		uintptr(cryptMsg),
		CMSG_SIGNER_INFO_PARAM,
		0,
		uintptr(unsafe.Pointer(&signerInfoBuf[0])),
		uintptr(unsafe.Pointer(&signerInfoSize)),
	)
	if r == 0 {
		return ""
	}

	// CMSG_SIGNER_INFO structure starts with dwVersion(4), Issuer(CRYPT_DATA_BLOB), SerialNumber(CRYPT_DATA_BLOB)
	// On 64-bit: offset 0: dwVersion(4) + pad(4) + Issuer.cbData(8) + Issuer.pbData(8) + SerialNumber.cbData(8) + SerialNumber.pbData(8) = 40 bytes to reach HashAlgorithm...
	// This is complex; use a simpler approach: use CertFindCertificateInStore with the signer info

	// Simpler: just use the signer info Issuer + SerialNumber to find the cert
	type cryptDataBlob struct {
		cbData uint64
		pbData uintptr
	}
	type signerInfo struct {
		dwVersion    uint32
		_            [4]byte
		issuer       cryptDataBlob
		serialNumber cryptDataBlob
	}

	si := (*signerInfo)(unsafe.Pointer(&signerInfoBuf[0]))

	type certInfo struct {
		issuer       cryptDataBlob
		serialNumber cryptDataBlob
	}
	ci := certInfo{
		issuer:       si.issuer,
		serialNumber: si.serialNumber,
	}

	certCtx, err := windows.CertFindCertificateInStore(
		windows.Handle(certStore),
		windows.X509_ASN_ENCODING|windows.PKCS_7_ASN_ENCODING,
		0,
		windows.CERT_FIND_SUBJECT_CERT,
		unsafe.Pointer(&ci),
		nil,
	)
	if err != nil || certCtx == nil {
		return ""
	}
	defer procCertFreeCertificateContext.Call(uintptr(unsafe.Pointer(certCtx)))

	nameBuf := make([]uint16, 256)
	r, _, _ = procCertGetNameStringW.Call(
		uintptr(unsafe.Pointer(certCtx)),
		CERT_NAME_SIMPLE_DISPLAY_TYPE,
		0,
		0,
		uintptr(unsafe.Pointer(&nameBuf[0])),
		256,
	)
	if r <= 1 {
		return ""
	}
	return windows.UTF16ToString(nameBuf)
}

func getVersionInfo(path string, info *SignatureInfo) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return
	}

	size, _, _ := procGetFileVersionInfoSizeW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
	)
	if size == 0 {
		return
	}

	data := make([]byte, size)
	r, _, _ := procGetFileVersionInfoW.Call(
		uintptr(unsafe.Pointer(pathPtr)),
		0,
		size,
		uintptr(unsafe.Pointer(&data[0])),
	)
	if r == 0 {
		return
	}

	info.Company = queryStringValue(data, "CompanyName")
	info.Product = queryStringValue(data, "ProductName")
	origName := queryStringValue(data, "OriginalFilename")
	// Windows MUI resource files report OriginalFilename with .mui suffix — strip it
	if len(origName) > 4 && strings.EqualFold(origName[len(origName)-4:], ".mui") {
		origName = origName[:len(origName)-4]
	}
	info.OriginalName = origName
	info.FileVersion = queryStringValue(data, "FileVersion")
}

func queryStringValue(data []byte, name string) string {
	// Try common language/codepage combinations
	langCodePages := []string{
		"040904B0", // English, Unicode
		"040904E4", // English, Latin1
		"000004B0", // Neutral, Unicode
		"080404B0", // Chinese, Unicode
		"040904b0",
	}

	for _, lcp := range langCodePages {
		subBlock := `\StringFileInfo\` + lcp + `\` + name
		val := queryValue(data, subBlock)
		if val != "" {
			return val
		}
	}

	// Try to get the translation table
	transBlock := `\VarFileInfo\Translation`
	transPtr, err := windows.UTF16PtrFromString(transBlock)
	if err != nil {
		return ""
	}

	var transData unsafe.Pointer
	var transLen uint32
	r, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(transPtr)),
		uintptr(unsafe.Pointer(&transData)),
		uintptr(unsafe.Pointer(&transLen)),
	)
	if r != 0 && transLen >= 4 {
		type langCodePage struct {
			Language uint16
			CodePage uint16
		}
		lcp := (*langCodePage)(transData)
		subBlock := fmt.Sprintf(`\StringFileInfo\%04x%04x\%s`, lcp.Language, lcp.CodePage, name)
		return queryValue(data, subBlock)
	}

	return ""
}

func queryValue(data []byte, subBlock string) string {
	subBlockPtr, err := windows.UTF16PtrFromString(subBlock)
	if err != nil {
		return ""
	}

	var valuePtr unsafe.Pointer
	var valueLen uint32
	r, _, _ := procVerQueryValueW.Call(
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(unsafe.Pointer(subBlockPtr)),
		uintptr(unsafe.Pointer(&valuePtr)),
		uintptr(unsafe.Pointer(&valueLen)),
	)
	if r == 0 || valueLen == 0 {
		return ""
	}

	u16 := unsafe.Slice((*uint16)(valuePtr), valueLen)
	return windows.UTF16ToString(u16)
}
