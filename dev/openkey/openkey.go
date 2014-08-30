// Go bindings for the libopenkey. These bindings use the libfreefare bindings
// from package github.com/fuzxxl/freefare/0.2/freefare. Please notice that
// these bindings ship their own copy of the libopenkey.
package openkey

// #cgo LDFLAGS: -lnfc -lfreefare -luuid -lgcrypt
// #cgo CFLAGS: -std=gnu99
// #include <stdlib.h>
// #include <gcrypt.h>
// #include "openkey.h"
import "C"
import "sort"
import "strconv"
import "unsafe"

import "github.com/fuzxxl/freefare/0.3/freefare"

// Roles
const (
	CardProducer = iota
	LockManager
	CardAuthenticator
)

// An error code caused by the libopenkey. This is usually the negated return
// value.
type Error int

// Internal veriable to avoid calling initGcrypt() too often
var gcryptInited = false

// Returns a human-readable string describing the error. The strings returned
// by this function are not guaranteed to remain stable.
func (e Error) Error() string {
	return "openkey error #" + strconv.Itoa(int(e))
}

// An openkey context. This type wraps openkey_context_t. Allocate an object of
// this type using the New() function.
type Context struct {
	cptr *C.openkey_context_t
}

// Create a new openkey context. This function wraps openkey_context_init(). If
// initialization of the context fails, this function panics. A context
// allocated with New() must be released after use with Close().
func New() Context {
	ctxtptr := C.openkey_init()
	if ctxtptr == nil {
		panic("Could not create openkey.Context: C.openkey_init() failed")
	}

	gcryptInited = true
	return Context{&ctxtptr}
}

// Release an openkey context. This function wraps openkey_context_fini(). This
// function fails with an error iff the context has already been closed. It is
// save to ignore any errors coming from this function.
//
// Usage of a context after Close() results in an error.
func (c Context) Close() error {
	r := C.openkey_fini(*c.cptr)
	if r != 0 {
		return Error(-r)
	}

	*c.cptr = nil
	return nil
}

// Add a role to an openkey context. For a description of the possible errors,
// have a look at libopenkey.c. There is no documentation but you can possibly
// figure out where your error came from if you look long enough.
func (c Context) AddRole(role int, privateBasePath string) error {
	cpbp := C.CString(privateBasePath)
	defer C.free(unsafe.Pointer(cpbp))

	r := C.openkey_role_add(*c.cptr, C.enum_openkey_role(role), cpbp)
	if r != 0 {
		return Error(-r)
	}

	return nil
}

// Has a producer role been bootstrapped? This function also returns false if
// c has already been closed.
func (c Context) IsProducerBootstrapped() bool {
	return bool(C.openkey_producer_is_bootstrapped(*c.cptr))
}

// Bootstrap a producer role. This function returns true if the producer role of
// c had already been bootstrapped before.
func (c Context) BootstrapProducer() (bool, error) {
	r := C.openkey_producer_bootstrap(*c.cptr)
	switch {
	case r > 0:
		return true, nil
	case r == 0:
		return false, nil
	default:
		return false, Error(-r)
	}
}

// Create an openkey card. This function may either return an Error object or
// any of the error objects freefare.Tag.TranslateError() may return; the
// wrapper automatically translates error codes to a freefare.Error if it finds
// that the error was produced by the libfreefare.
func (c Context) ProducerCardCreate(tag freefare.DESFireTag, cardName string) error {
	ccn := C.CString(cardName)
	defer C.free(unsafe.Pointer(ccn))

	r, err := C.openkey_producer_card_create(*c.cptr, tagptr(tag), ccn)
	if r >= 0 {
		return nil
	}

	// figure out if error comes from the MifareTag. The following return
	// codes have been found to come from operatons on tag. If err == nil,
	// i.e. errno not set, we return the openkey error code instead as it
	// gives us more than just an "unknown error".
	if err == nil {
		return Error(-r)
	}

	tagErrors := []int{
		4, 5, 12, 13, 15, 16, 17, 18, 19, 20, 21,
		23, 24, 25, 26, 27, 28, 29, 30, 31, 31, 34}

	index := sort.SearchInts(tagErrors, int(-r))
	if index < len(tagErrors) && tagErrors[index] == int(-r) {
		return tag.TranslateError(err)
	}

	return Error(-r)
}

// Recreate an openkey card. This function may either return an Error object or
// any of the error objects freefare.Tag.TranslateError() may return; the
// wrapper automatically translates error codes for this function. Notice that
// since the implementation of openkey_producer_card_recreate() does not
// distinguish between different errors, the translation is a little bit
// inexact. Specifically, the translation routine looks for errno and translates
// the error code if errno is set. Since versions of the libfreefare up to 0.4.0
// do not set errno on authentication failure, error reporting might be wrong.
func (c Context) ProducerCardRecreate(tag freefare.DESFireTag, cardName, oldId string) error {
	ccn := C.CString(cardName)
	defer C.free(unsafe.Pointer(ccn))

	cid := C.CString(oldId)
	defer C.free(unsafe.Pointer(cid))

	r, err := C.openkey_producer_card_recreate(*c.cptr, tagptr(tag), ccn, cid)
	if r >= 0 {
		return nil
	}

	if err == nil {
		return Error(-r)
	}

	return tag.TranslateError(err)
}

// Has a manager role been bootstrapped? This function also returns false if
// c has already been closed.
func (c Context) IsManagerBootstrapped() bool {
	return bool(C.openkey_manager_is_bootstrapped(*c.cptr))
}

// Bootstrap a manager role. This function returns true if the producer role of
// c had already been bootstrapped before.
func (c Context) BootstrapManager(preferredSlot int) (bool, error) {
	r := C.openkey_manager_bootstrap(*c.cptr, C.int(preferredSlot))
	switch {
	case r > 0:
		return true, nil
	case r == 0:
		return false, nil
	default:
		return false, Error(-r)
	}
}

// Own a card. This function wraps openkey_manager_card_own_pw(). To own a card
// without a password (as with openkey_manager_card_own()), pass nil for pw.
// This function may either return an Error object or any of the error objects
// freefare.Tag.TranslateError() may return; the wrapper automatically
// translates error codes to a freefare.Error if it finds that the error was
// produced by the libfreefare.
func (c Context) ManagerOwnCard(tag freefare.DESFireTag, slot int, keyFile string, pw []byte) error {
	ckf := C.CString(keyFile)
	defer C.free(unsafe.Pointer(ckf))

	var pwptr *C.uint8_t
	if len(pw) > 0 {
		pwptr = (*C.uint8_t)(&pw[0])
	}

	r, err := C.openkey_manager_card_own_pw(
		*c.cptr, tagptr(tag), C.int(slot), ckf, pwptr, C.size_t(len(pw)))

	if err != nil && (r == -1 || r == -4) {
		return tag.TranslateError(err)
	}

	return Error(-r)
}

// Figure out if a card has an authenticator role added. This function also
// returns false if c has already been closed. The name of this function is a
// bit strange and has been taken verbatim from the C code.
func (c Context) PrepareAuthenticator() bool {
	return C.openkey_authenticator_prepare(*c.cptr) == 1
}

// Use a card for authentication. This function fails if no authenticator role
// has been added to the context. This function wraps
// openkey_authenticator_authenticate_pw(). To get the functionality of
// openkey_authenticator_authenticate(), pass nil for pw. This function may
// either return an Error object or any of the error objects
// freefare.Tag.TranslateError() may return; the wrapper automatically
// translates error codes to a freefare.Error if it finds that the error was
// produced by the libfreefare.
func (c Context) AuthenticateCard(tag freefare.DESFireTag, pw []byte) (cardId string, err error) {
	var cid *C.char
	var pwptr *C.uint8_t
	if len(pw) > 0 {
		pwptr = (*C.uint8_t)(&pw[0])
	}

	r, err := C.openkey_authenticator_card_authenticate_pw(
		*c.cptr, tagptr(tag), &cid, pwptr, C.size_t(len(pw)))

	if r >= 0 {
		str := C.GoString(cid)
		C.free(unsafe.Pointer(cid))
		return str, nil
	}

	if err != nil && (r == -2 || r == -3) {
		return "", tag.TranslateError(err)
	}

	return "", Error(-r)
}

// This function wraps the function openkey_kdf(). As a side-effect, this
// function intializes the libgrypt as some of its functions are needed for this
// function.
func Kdf(masterKey []byte, aid uint32, keyNo byte, data, derivedKey []byte) error {
	initGcrypt()

	r := C.openkey_kdf(
		(*C.uint8_t)(&masterKey[0]), C.size_t(len(masterKey)),
		C.uint32_t(aid), C.uint8_t(keyNo),
		(*C.uint8_t)(&data[0]), C.size_t(len(data)),
		(*C.uint8_t)(&derivedKey[0]), C.size_t(len(derivedKey)))

	if r == 0 {
		return nil
	}

	return Error(-r)
}

// This function wraps the function openkey_pbkdf(). As a side-effect, this
// function intializes the libgcrypt as some of its functions are needed for
// this function.
func Pbkdf(
	masterKey []byte,
	aid uint32, keyNo byte,
	data, pw []byte,
	iterations int,
	derivedKey []byte,
) error {
	initGcrypt()

	r := C.openkey_pbkdf(
		(*C.uint8_t)(&masterKey[0]), C.size_t(len(masterKey)),
		C.uint32_t(aid), C.uint8_t(keyNo),
		(*C.uint8_t)(&data[0]), C.size_t(len(data)),
		(*C.uint8_t)(&pw[0]), C.size_t(len(pw)),
		C.int(iterations),
		(*C.uint8_t)(&derivedKey[0]), C.size_t(len(derivedKey)))

	if r == 0 {
		return nil
	}

	return Error(-r)
}

// Get a pointer to the underlying MifareTag
func tagptr(t freefare.DESFireTag) C.MifareTag {
	return C.MifareTag(unsafe.Pointer(t.Pointer()))
}

// initialize the libgcrypt, panic if that fails
func initGcrypt() {
	if gcryptInited {
		return
	}

	if C.gcry_check_version(nil) == nil {
		panic("Could not initilize libgcrypt")
	}

	gcryptInited = true
}
