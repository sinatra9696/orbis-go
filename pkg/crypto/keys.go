package crypto

import (
	gocrypto "crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"io"
	"strings"

	cometcrypto "github.com/cometbft/cometbft/crypto"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	ic "github.com/libp2p/go-libp2p/core/crypto"
	icpb "github.com/libp2p/go-libp2p/core/crypto/pb"
	"go.dedis.ch/kyber/v3"
	"go.dedis.ch/kyber/v3/share"
	"go.dedis.ch/kyber/v3/suites"
	"golang.org/x/crypto/ripemd160"
)

type KeyType = icpb.KeyType

func KeyTypeFromString(keyType string) (KeyType, error) {
	switch strings.ToLower(keyType) {
	case "ed25519":
		return Ed25519, nil
	case "ecdsa":
		return ECDSA, nil
	case "secp256k1":
		return Secp256k1, nil
	default:
		return 0, ErrBadKeyType
	}
}

var (
	Ed25519   = icpb.KeyType_Ed25519
	ECDSA     = icpb.KeyType_ECDSA
	Secp256k1 = icpb.KeyType_Secp256k1
)

// PublicKey
type PublicKey interface {
	ic.PubKey
	Point() kyber.Point
	Std() (gocrypto.PublicKey, error)
}

type pubKey struct {
	ic.PubKey
	suite suites.Suite
}

// PublicKeyFromLibP2P creates a PublicKey from a given
// LibP2P based PubKey
func PublicKeyFromLibP2P(pubkey ic.PubKey) (PublicKey, error) {
	return publicKeyFromLibP2P(pubkey)
}

func PublicKeyFromProto(pk *icpb.PublicKey) (PublicKey, error) {
	icpk, err := ic.PublicKeyFromProto(pk)
	if err != nil {
		return nil, err
	}
	return publicKeyFromLibP2P(icpk)
}

func PublicKeyFromStdPublicKey(pubkey gocrypto.PublicKey) (PublicKey, error) {
	var icpk ic.PubKey
	var err error
	switch pkt := pubkey.(type) {
	case ed25519.PublicKey:
		icpk, err = ic.UnmarshalEd25519PublicKey(pkt)
	case ecdsa.PublicKey:
		icpk, err = ic.ECDSAPublicKeyFromPubKey(pkt)
	case *ecdsa.PublicKey:
		icpk, err = ic.ECDSAPublicKeyFromPubKey(*pkt)
	case secp256k1.PublicKey:
		sppk := ic.Secp256k1PublicKey(pkt)
		icpk = &sppk
	case *secp256k1.PublicKey:
		icpk = (*ic.Secp256k1PublicKey)(pkt)
	default:
		return nil, fmt.Errorf("unknown key type")
	}

	if err != nil {
		return nil, err
	}

	return publicKeyFromLibP2P(icpk)
}

func PublicKeyFromPoint(suite suites.Suite, point kyber.Point) (PublicKey, error) {

	buf, err := point.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("marshal point: %w", err)
	}

	var pk ic.PubKey

	switch strings.ToLower(suite.String()) {
	case "ed25519":
		pk, err = ic.UnmarshalEd25519PublicKey(buf)
	case "secp256k1":
		pk, err = ic.UnmarshalSecp256k1PublicKey(buf)
	case "ecdsa":
		pk, err = ic.UnmarshalECDSAPublicKey(buf)
	case "rsa":
		pk, err = ic.UnmarshalRsaPublicKey(buf)
	default:
		return nil, ErrBadKeyType
	}

	if err != nil {
		return nil, fmt.Errorf("unmarshal public key: %w", err)
	}

	return PublicKeyFromLibP2P(pk)
}

func PublicKeyFromBytes(keyType string, buf []byte) (PublicKey, error) {
	var pk ic.PubKey
	var err error
	switch strings.ToLower(keyType) {
	case "ed25519":
		pk, err = ic.UnmarshalEd25519PublicKey(buf)
	case "secp256k1":
		pk, err = ic.UnmarshalSecp256k1PublicKey(buf)
	case "ecdsa":
		pk, err = ic.UnmarshalECDSAPublicKey(buf)
	case "rsa":
		pk, err = ic.UnmarshalRsaPublicKey(buf)
	default:
		return nil, ErrBadKeyType
	}

	if err != nil {
		return nil, fmt.Errorf("public key from bytes: %w", err)
	}

	return PublicKeyFromLibP2P(pk)
}

func publicKeyFromLibP2P(pubkey ic.PubKey) (*pubKey, error) {
	suite, err := SuiteForType(pubkey.Type())
	if err != nil {
		return nil, err
	}

	return &pubKey{
		PubKey: pubkey,
		suite:  suite,
	}, nil

}

func PublicKeyToProto(pk PublicKey) (*icpb.PublicKey, error) {
	return ic.PublicKeyToProto(pk)
}

func (p *pubKey) Point() kyber.Point {
	fmt.Println("pubkey.Point(): suite:", p.suite.String())
	buf, _ := p.PubKey.Raw()
	point := p.suite.Point()
	point.UnmarshalBinary(buf)
	return point
}

func (p *pubKey) Std() (gocrypto.PublicKey, error) {
	// our version of "standard" secp256k1 keys uses the
	// dcred type directly, as its more common among our
	// dependencies (like go-jose)
	switch pk := p.PubKey.(type) {
	case *ic.Secp256k1PublicKey:
		return (*secp256k1.PublicKey)(pk), nil
	}
	return ic.PubKeyToStdKey(p.PubKey)
}

type libp2pPrivKey interface {
	ic.Key
	Sign([]byte) ([]byte, error)
}

type PrivateKey interface {
	libp2pPrivKey
	Scalar() kyber.Scalar
	GetPublic() PublicKey
	// Std() gocrypto.PrivateKey
}

type privKey struct {
	ic.PrivKey
	suite suites.Suite
}

func GenerateKeyPair(ste suites.Suite, src io.Reader) (PrivateKey, PublicKey, error) {
	keyType, err := KeyTypeFromString(ste.String())
	if err != nil {
		return nil, nil, err
	}
	sk, pk, err := ic.GenerateKeyPairWithReader(int(keyType), 0, src)
	if err != nil {
		return nil, nil, err
	}

	return &privKey{
			PrivKey: sk,
			suite:   ste,
		}, &pubKey{
			PubKey: pk,
			suite:  ste,
		}, nil
}

func PrivateKeyFromBytes(keyType string, buf []byte) (PrivateKey, error) {
	var pk ic.PrivKey
	var err error
	switch strings.ToLower(keyType) {
	case "ed25519":
		pk, err = ic.UnmarshalEd25519PrivateKey(buf)
	case "secp256k1":
		pk, err = ic.UnmarshalSecp256k1PrivateKey(buf)
	case "ecdsa":
		pk, err = ic.UnmarshalECDSAPrivateKey(buf)
	case "rsa":
		pk, err = ic.UnmarshalRsaPrivateKey(buf)
	default:
		return nil, ErrBadKeyType
	}

	if err != nil {
		return nil, fmt.Errorf("public key from bytes: %w", err)
	}

	return PrivateKeyFromLibP2P(pk)
}

func PrivateKeyFromLibP2P(privkey ic.PrivKey) (PrivateKey, error) {
	suite, err := SuiteForType(privkey.Type())
	if err != nil {
		return nil, err
	}

	return &privKey{
		PrivKey: privkey,
		suite:   suite,
	}, nil
}

// Scalar returns a numeric elliptic curve scalar
// representation of the private key.
//
// WARNING: THIS ONLY WORDS WITH ED25519 & SECP256K1 CURVES RIGHT NOW.
func (p *privKey) Scalar() kyber.Scalar {
	switch p.Type() {
	case icpb.KeyType_Ed25519:
		return p.ed25519Scalar()
	case icpb.KeyType_Secp256k1:
		return p.secp256k1Scalar()
	default:
		panic("only ed25519 and secp256k1 private key scalar conversion supported")
	}
}

func (p *privKey) secp256k1Scalar() kyber.Scalar {
	buf, err := p.Raw()
	if err != nil {
		panic(err) // todo
	}

	return p.suite.Scalar().SetBytes(buf)
}

func (p *privKey) ed25519Scalar() kyber.Scalar {
	// There is a discrepency between LibP2P private keys
	// and "raw" EC scalars. LibP2P private keys is an
	// (x, y) pair, where x is the given "seed" and y is
	// the cooresponding publickey. Where y is computed as
	//
	// h := sha512.Hash(x)
	// s := scalar().SetWithClamp(h)
	// y := point().ScalarBaseMul(x)
	//
	// So to make sure future conversions of this scalar
	// to a public key, like in the DKG setup, we need to
	// convert this key to a scalar using the Hash and Clamp
	// method.
	//
	// To understand clamping, see here:
	// https://neilmadden.blog/2020/05/28/whats-the-curve25519-clamping-all-about/

	buf, err := p.PrivKey.Raw()
	if err != nil {
		panic(err)
	}

	// hash seed and clamp bytes
	digest := sha512.Sum512(buf[:32])
	digest[0] &= 0xf8
	digest[31] &= 0x7f
	digest[31] |= 0x40
	return p.suite.Scalar().SetBytes(digest[:32])
}

func (p *privKey) GetPublic() PublicKey {
	return &pubKey{
		PubKey: p.PrivKey.GetPublic(),
		suite:  p.suite,
	}
}

// DistKeyShare
type DistKeyShare struct {
	// Coefficients of the public polynomial holding the public key
	Commits []kyber.Point

	// PriShare of the distributed secret
	PriShare *share.PriShare
}

// PubPoly
type PubPoly struct {
	*share.PubPoly
}

func PubkeyBytesToBech32(pubkey []byte) (string, error) {
	// convert to address
	sha := sha256.Sum256(pubkey)
	hasherRIPEMD160 := ripemd160.New()
	hasherRIPEMD160.Write(sha[:]) // does not error
	buf := cometcrypto.Address(hasherRIPEMD160.Sum(nil))
	addr := sdk.AccAddress(buf)
	// convert to bech32 (stringified address)
	return addr.String(), nil
}
