package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"

	ic "github.com/libp2p/go-libp2p/core/crypto"
	"github.com/libp2p/go-libp2p/core/peer"
	libp2ptls "github.com/libp2p/go-libp2p/p2p/security/tls"
)

const ( // raw values of private keys used as identity keys
	Ed25519Priv = "e8c9bf5ba295dbe3a8b0bf24a08910e3a01618ee74bd25f671a6b492b51137bfa77f1d92fedb59dddaea5a1c4abd1ac2fbde7d7b879ed364501809923d7c11b9"
	EDSAPriv    = "307702010104206849bb3add13509b076d7e6a2b1554c8c219aa03e9b9f1e94f3cca8284197199a00a06082a8648ce3d030107a14403420004bf30511f909414ebdd3242178fd290f093a551cf75c973155de0bb5a96fedf6cb5d52da7563e794b512f66e60c7f55ba8a3acf3dd72a801980d205e8a1ad29f2"
	RSAPriv     = "308204a30201000282010100c6423f0fa8757d15b9e9332126339f32395b3f5d16e639b9d030e0507e60e68c973607dad6a2994a5b5f80456de271f21faee9051807e846ade5b396c661eef046e1f8f2279182df845f8962040cf08f6cfadcfde9c4592a0d11b92edab459e9099535db595834c8db762136a164f159bb01a5545a24e0f453df420e6633a9cbc123454b68c11966bc9851993608875e804cfe65604ac60f357b226ba57de0c191039935f7c0c85f1d3de7c2aeb7e6a1520f7201542b949784feb85d53d99f034a55218e6c4fae870cddf7dbb43583cd9eb1bc9e5111c0e7cf62aafef1188711ba205b87c8c95a4ccf154881a49e8b155c795fc1c7621b3b95b01ce4af48a6a70203010001028201007b5a6c72099650255c6ec3e934239a415d7e708632e13bb968d7803994e8258a03eb12280eb34c3cff6d041a2eac5dc90ffd7bee376d740fc5d2cd525a4c44a62af41e384c7634bf6d5523dd6037ccd4f031859e55fc5c9dd553d9ac55573139d5448925d909108e883d8f9cb5fe604c3c16620f81a6c070445efc7289144be7e8646a5bf6702e44edb4967e0c3cfbdb66a672501423aef2c53443d7fcaaf2826608d243becb71b546684042d6641174c9914dfc0632d20bae277d9f1ee33ea320e256b35a00bb09e0869404dbb1cdef31055e42eddad1f3d6e71a44e65bf54d2ce13fbd2c6b898707623ac756c7b22f0dbf89af3c9ab0b82b2f5b0c48ce9c8102818100fad9645884995b4ffac31dfc68322c26b8bd651bfef539bc0b124f088f6ed587a5a3365877f22950f333a54dfee1144d9b6cb15d2856c8c6d87355cec1cf4e441f040990c819c329d6186b16759b9c394c08f2d2c11eb161e80f214e426fcc5c2c9d680c9069dc4744722b2666cfda1391363b78f8e7de37f973467a50718ef902818100ca5468a7f318b20d8a79837467cf5fd613306a48e33e868226992fb9ac0398fac84c7eb637562d570a76b47fb1dae40d209fb109b37f7616e35ef63a9d7a153d56c72064997ca7d831b22f3a92c9a8b0ceb0202e6e431f19f6a06d0953983b7b06b741d7dc4138176a88fbd89845113269aec75febcc129b10f708f848ac2a9f02818026a0cb5f062c476f6d82166003fb95e8f091d9bc11ead95527af4e1457620de7b18e0c945b0423709fc2d835c6860a8658e4c7fb3c7700bbfe20e499ce268a3adb3bd7ed3fa317f69d4d6d502c14265e7c62f46197f38e0531a302d1f65118fb28b3a48e2abee278e7055db7b02559c3a19ce453a0a0b40b929239cc240f18a102818100a2616e00e46bfc723ba15c2bef28925ca7d7e2650ee3de65d3fe7b3c035e7bc7413b8b324865044c67dc6eee50da40ce7c514d6f60bcba149274631f15c5a6082d7df0746c6e8bf249a81c9960b731887cc9037ae009448bbcd071d1db6240d272c85eb294554f64139f4ea83d44a9119199b0ef3db9f170bc03d712149900370281806d57a9aad3e6c2055e923f7b942181a9339dc7378d7dc846046437fd349f32c4a936889ea5ae9c9716a8fe31c830042302d1bc4c9b2d81eac0234269ec27d87d8962a92a40aa9db767ca9f74d78a7b434eae98f01bad0b2a1e9b5db144e78221852f3159e5e98828fc175d5e1b7e06a19e3f751431e9849c950da565c11f487d"
	Secp256k1   = "8d7e1f8aa7af251fbd2039e6856d405dd774dbecceef8c580ddd6d718e56d184"
)

func main() {
	rand.Reader = &RandMockReader{false} // mock reader since EDSA will use it

	fmt.Printf("\n\n====== Ed25519 Peer:\n")
	data, err := hex.DecodeString(Ed25519Priv)
	panicIfError(err)
	key, err := ic.UnmarshalEd25519PrivateKey(data)
	panicIfError(err)
	generate(key, false)

	fmt.Printf("\n\n====== ECDSA Peer:\n")
	data, err = hex.DecodeString(EDSAPriv)
	panicIfError(err)
	key, err = ic.UnmarshalECDSAPrivateKey(data)
	panicIfError(err)
	generate(key, false)

	fmt.Printf("\n\n====== Secp256k1 Peer:\n")
	data, err = hex.DecodeString(Secp256k1)
	panicIfError(err)
	key, err = ic.UnmarshalSecp256k1PrivateKey(data)
	panicIfError(err)
	generate(key, false)

	fmt.Printf("\n\n====== RSA Peer:\n")
	data, err = hex.DecodeString(RSAPriv)
	panicIfError(err)
	key, err = ic.UnmarshalRsaPrivateKey(data)
	panicIfError(err)
	generate(key, false)

	fmt.Printf("\n\n====== Invalid certifiacte:\n")
	data, err = hex.DecodeString(EDSAPriv)
	panicIfError(err)
	key, err = ic.UnmarshalECDSAPrivateKey(data)
	panicIfError(err)
	generate(key, true)
}

func panicIfError(err error) {
	if err != nil {
		panic(err)
	}
}

func generate(priv ic.PrivKey, isInvalid bool) {
	pid, err := peer.IDFromPrivateKey(priv)
	panicIfError(err)

	pr, err := priv.Raw()
	panicIfError(err)

	cert := makeCertificate(priv, isInvalid)

	fmt.Printf("Private key bytes: %s\n", hex.EncodeToString(pr))
	fmt.Printf("Peer ID: %s\n", pid)
	fmt.Printf("Cert bytes:\n%v\n", hex.EncodeToString(cert.Certificate[0]))
	print(cert)
}

func print(cert *tls.Certificate) {
	x509cert, err := x509.ParseCertificate(cert.Certificate[0])
	panicIfError(err)

	fmt.Println("Certificate Details:")
	fmt.Printf("Issuer: %s\n", x509cert.Issuer)
	fmt.Printf("Subject: %s\n", x509cert.Subject)
	fmt.Printf("Serial Number: %s\n", x509cert.SerialNumber)
	fmt.Printf("Not Before: %s\n", x509cert.NotBefore)
	fmt.Printf("Not After: %s\n", x509cert.NotAfter)
	fmt.Printf("Public Key Algorithm: %s\n", x509cert.PublicKeyAlgorithm)
	fmt.Printf("Signature Algorithm: %s\n", x509cert.SignatureAlgorithm)
}

func makeCertificate(identityKey ic.PrivKey, isInvalid bool) *tls.Certificate {
	// certificate key will always be the same since mock random is used
	certKey, err := ecdsa.GenerateKey(elliptic.P256(), &RandMockReader{})
	panicIfError(err)

	extensionCertPublic := certKey.Public()
	if isInvalid {
		// for invalid certificate we have to create new cert key and use it's public
		// key in extension signature
		certKeyInvalid, err := ecdsa.GenerateKey(elliptic.P256(), &RandMockReader{true})
		panicIfError(err)
		extensionCertPublic = certKeyInvalid.Public()
	}

	certTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1234567890),
		NotBefore:    time.Unix(157813200, 0).UTC(),
		NotAfter:     time.Unix(67090165200, 0).UTC(),
		// According to RFC 3280, the issuer field must be set,
		// see https://datatracker.ietf.org/doc/html/rfc3280#section-4.1.2.4.
		Subject: pkix.Name{
			Organization: []string{"libp2p.io"},
			SerialNumber: "1",
		},
	}
	extension, err := libp2ptls.GenerateSignedExtension(identityKey, extensionCertPublic)
	panicIfError(err)

	certTmpl.ExtraExtensions = append(certTmpl.ExtraExtensions, extension)

	certDER, err := x509.CreateCertificate(&RandMockReader{}, certTmpl, certTmpl, certKey.Public(), certKey)
	panicIfError(err)

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  certKey,
	}
}

type RandMockReader struct {
	isInvalid bool
}

func (r *RandMockReader) Read(p []byte) (n int, err error) {
	if len(p) <= 1 { // randutil.MaybeReadByte(rand) hack
		return 1, nil
	}

	for i := range p {
		if r.isInvalid {
			p[i] = 31
		} else {
			p[i] = 42
		}
	}

	return len(p), nil
}
