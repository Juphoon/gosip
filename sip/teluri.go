package sip

import (
	"bytes"

	"github.com/Juphoon/gosip/util"
)

// TelUri
// A SIP or SIPS URI, including all params and URI header params.
//noinspection GoNameStartsWithPackageName
type TelUri struct {
	// True if and only if the URI is a SIPS URI.
	FIsEncrypted bool

	// The user part of the URI: the 'joe' in sip:joe@bloggs.com
	// This is a pointer, so that URIs without a user part can have 'nil'.
	FUser MaybeString

	// The password field of the URI. This is represented in the URI as joe:hunter2@bloggs.com.
	// Note that if a URI has a password field, it *must* have a user field as well.
	// This is a pointer, so that URIs without a password field can have 'nil'.
	// Note that RFC 3261 strongly recommends against the use of password fields in SIP URIs,
	// as they are fundamentally insecure.
	FPassword MaybeString

	// The host part of the URI. This can be a domain, or a string representation of an IP address.
	FHost string

	// The port part of the URI. This is optional, and so is represented here as a pointer type.
	FPort *Port

	// Any parameters associated with the URI.
	// These are used to provide information about requests that may be constructed from the URI.
	// (For more details, see RFC 3261 section 19.1.1).
	// These appear as a semicolon-separated list of key=value pairs following the host[:port] part.
	FUriParams Params

	// Any headers to be included on requests constructed from this URI.
	// These appear as a '&'-separated list at the end of the URI, introduced by '?'.
	// Although the values of the map are MaybeStrings, they will never be NoString in practice as the parser
	// guarantees to not return blank values for header elements in SIP URIs.
	// You should not set the values of headers to NoString.
	FHeaders Params
}

func (uri *TelUri) IsEncrypted() bool {
	return uri.FIsEncrypted
}

func (uri *TelUri) SetEncrypted(flag bool) {
	uri.FIsEncrypted = flag
}

func (uri *TelUri) User() MaybeString {
	return uri.FUser
}

func (uri *TelUri) SetUser(user MaybeString) {
	uri.FUser = user
}

func (uri *TelUri) Password() MaybeString {
	return uri.FPassword
}

func (uri *TelUri) SetPassword(pass MaybeString) {
	uri.FPassword = pass
}

func (uri *TelUri) Host() string {
	return uri.FHost
}

func (uri *TelUri) SetHost(host string) {
	uri.FHost = host
}

func (uri *TelUri) Port() *Port {
	return uri.FPort
}

func (uri *TelUri) SetPort(port *Port) {
	uri.FPort = port
}

func (uri *TelUri) UriParams() Params {
	return uri.FUriParams
}

func (uri *TelUri) SetUriParams(params Params) {
	uri.FUriParams = params
}

func (uri *TelUri) Headers() Params {
	return uri.FHeaders
}

func (uri *TelUri) SetHeaders(params Params) {
	uri.FHeaders = params
}

func (uri *TelUri) IsWildcard() bool {
	return false
}

// Determine if the SIP URI is equal to the specified URI according to the rules laid down in RFC 3261 s. 19.1.4.
// TODO: The Equals method is not currently RFC-compliant; fix this!
func (uri *TelUri) Equals(val interface{}) bool {
	otherPtr, ok := val.(*TelUri)
	if !ok {
		return false
	}

	if uri == otherPtr {
		return true
	}
	if uri == nil && otherPtr != nil || uri != nil && otherPtr == nil {
		return false
	}

	other := *otherPtr
	result := uri.FIsEncrypted == other.FIsEncrypted &&
		uri.FUser == other.FUser &&
		uri.FPassword == other.FPassword &&
		uri.FHost == other.FHost &&
		util.Uint16PtrEq((*uint16)(uri.FPort), (*uint16)(other.FPort))

	if !result {
		return false
	}

	if uri.FUriParams != otherPtr.FUriParams {
		if uri.FUriParams == nil {
			result = result && otherPtr.FUriParams != nil
		} else {
			result = result && uri.FUriParams.Equals(otherPtr.FUriParams)
		}
	}

	if uri.FHeaders != otherPtr.FHeaders {
		if uri.FHeaders == nil {
			result = result && otherPtr.FHeaders != nil
		} else {
			result = result && uri.FHeaders.Equals(otherPtr.FHeaders)
		}
	}

	return result
}

// Generates the string representation of a TelUri struct.
func (uri *TelUri) String() string {
	var buffer bytes.Buffer

	// Compulsory protocol identifier.
	buffer.WriteString("tel")
	buffer.WriteString(":")

	// Optional userinfo part.
	if user, ok := uri.FUser.(String); ok && user.String() != "" {
		buffer.WriteString(uri.FUser.String())
		if pass, ok := uri.FPassword.(String); ok && pass.String() != "" {
			buffer.WriteString(":")
			buffer.WriteString(pass.String())
		}
	}

	if (uri.FUriParams != nil) && uri.FUriParams.Length() > 0 {
		buffer.WriteString(";")
		buffer.WriteString(uri.FUriParams.ToString(';'))
	}

	if (uri.FHeaders != nil) && uri.FHeaders.Length() > 0 {
		buffer.WriteString("?")
		buffer.WriteString(uri.FHeaders.ToString('&'))
	}

	return buffer.String()
}

// Clone the Sip URI.
func (uri *TelUri) Clone() Uri {
	var newUri *TelUri
	if uri == nil {
		return newUri
	}

	newUri = &TelUri{
		FIsEncrypted: uri.FIsEncrypted,
		FUser:        uri.FUser,
		FPassword:    uri.FPassword,
		FHost:        uri.FHost,
		FUriParams:   cloneWithNil(uri.FUriParams),
		FHeaders:     cloneWithNil(uri.FHeaders),
	}
	if uri.FPort != nil {
		newUri.FPort = uri.FPort.Clone()
	}
	return newUri
}
