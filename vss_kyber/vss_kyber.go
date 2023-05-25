package vss_kyber

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"github.com/drand/kyber/group/mod"
	"github.com/drand/kyber/pairing"
	"math/big"
	"strings"

	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
)

type (
	PolynomialCoeff []kyber.Scalar
	Commitments     []kyber.Point
)

type Share struct {
	Index kyber.Scalar
	Value kyber.Scalar
}

func H3Tag() []byte {
	return []byte("IBE-H3")
}

func h3(s pairing.Suite, sigma, msg []byte) (kyber.Scalar, error) {
	h := s.Hash()

	if _, err := h.Write(H3Tag()); err != nil {
		return nil, fmt.Errorf("err hashing h3 tag: %v", err)
	}
	if _, err := h.Write(sigma); err != nil {
		return nil, fmt.Errorf("err hashing sigma: %v", err)
	}
	if _, err := h.Write(msg); err != nil {
		return nil, fmt.Errorf("err hashing msg: %v", err)
	}
	// we hash it a first time: buffer = hash("IBE-H3" || sigma || msg)
	buffer := h.Sum(nil)

	hashable, ok := s.G1().Scalar().(*mod.Int)
	if !ok {
		return nil, fmt.Errorf("unable to instantiate scalar as a mod.Int")
	}
	canonicalBitLen := hashable.MarshalSize() * 8
	actualBitLen := hashable.M.BitLen()
	toMask := canonicalBitLen - actualBitLen

	for i := uint16(1); i < 65535; i++ {
		h.Reset()
		// We will hash iteratively: H(i || H("IBE-H3" || sigma || msg)) until we get a
		// value that is suitable as a scalar.
		iter := make([]byte, 2)
		binary.LittleEndian.PutUint16(iter, i)
		_, _ = h.Write(iter)
		_, _ = h.Write(buffer)
		hashed := h.Sum(nil)
		// We then apply masking to our resulting bytes at the bit level
		// but we assume that toMask is a few bits, at most 8.
		// For instance when using BLS12-381 toMask == 1.
		if hashable.BO == mod.BigEndian {
			hashed[0] = hashed[0] >> toMask
		} else {
			hashed[len(hashed)-1] = hashed[len(hashed)-1] >> toMask
		}
		// NOTE: Here we unmarshal as a test if the buffer is within the modulo
		// because we know unmarshal does this test. This implementation
		// is almost generic if not for this line. TO make it truly generic
		// we would need to add methods to create a scalar from bytes without
		// reduction and a method to check if it is within the modulo on the
		// Scalar interface.
		if err := hashable.UnmarshalBinary(hashed); err == nil {
			return hashable, nil
		}
	}
	// if we didn't return in the for loop then something is wrong
	return nil, fmt.Errorf("rejection sampling failure")
}

func bigFromHex(hex string) *big.Int {
	if len(hex) > 1 && hex[:2] == "0x" {
		hex = hex[2:]
	}
	n, _ := new(big.Int).SetString(hex, 16)
	return n
}

func hexToBin(hexString string) string {
	hexChar2BinChar := map[string]string{
		"0": "0000",
		"1": "0001",
		"2": "0010",
		"3": "0011",
		"4": "0100",
		"5": "0101",
		"6": "0110",
		"7": "0111",
		"8": "1000",
		"9": "1001",
		"a": "1010",
		"b": "1011",
		"c": "1100",
		"d": "1101",
		"e": "1110",
		"f": "1111",
	}

	var binString bytes.Buffer
	hexStringArr := strings.Split(hexString, "")

	for i := 0; i < len(hexStringArr); i++ {
		binString.WriteString(hexChar2BinChar[hexStringArr[i]])
	}
	return binString.String()
}

func newPolynomial(threshold uint32) PolynomialCoeff {
	poly := make(PolynomialCoeff, threshold)
	for i := 0; i < len(poly); i++ {
		poly[i] = bls.NewKyberScalar()
	}
	return poly
}

func createRandomPolynomial(threshold uint32, masterSecretKey kyber.Scalar, groupOrder *big.Int) (poly PolynomialCoeff, err error) {
	if groupOrder.Sign() < 0 {
		return PolynomialCoeff{}, fmt.Errorf("group order is negative")
	}
	poly = newPolynomial(threshold)

	poly[0].Set(masterSecretKey)

	for i := 1; i < len(poly); i++ {
		one := big.NewInt(int64(1))
		max := big.NewInt(int64(0))
		max.Sub(groupOrder, one)

		r, err := rand.Int(rand.Reader, max)
		if err != nil {
			return PolynomialCoeff{}, err
		}
		r.Add(r, one)

		poly[i] = kyber.Scalar.SetInt64(poly[i], r.Int64())
	}
	return poly, nil
}

func (p PolynomialCoeff) eval(x kyber.Scalar) kyber.Scalar {
	y := bls.NewKyberScalar().Zero()

	for k := len(p) - 1; k >= 0; k-- {
		y.Mul(y, x)
		y.Add(y, p[k])
	}
	return y
}

func Exp(base, exponent kyber.Scalar) kyber.Scalar {
	if exponent.Equal(bls.NewKyberScalar().Zero()) {
		return bls.NewKyberScalar().One()
	}

	if exponent.Equal(bls.NewKyberScalar().One()) {
		return base
	}

	if base.Equal(bls.NewKyberScalar().One()) {
		return base
	}

	expBinStr := hexToBin(exponent.String())
	expBinStringArr := strings.Split(expBinStr, "")
	res := bls.NewKyberScalar().One()

	bPrime := bls.NewKyberScalar().One()
	bPrime.Mul(bPrime, base)

	for j := len(expBinStringArr) - 1; j >= 0; j-- {

		if expBinStringArr[j] == "1" {
			res.Mul(res, bPrime)
		}
		bPrime.Mul(bPrime, bPrime)
	}

	return res
}

func GenerateMSKAndMPK(groupOrder *big.Int) (masterSecretKey kyber.Scalar, masterPublicKey kyber.Point) {
	one := big.NewInt(int64(1))
	max := big.NewInt(int64(0))
	max.Sub(groupOrder, one)

	r, err := rand.Int(rand.Reader, max)
	if err != nil {
		fmt.Println("could not generate random master secret key")
		return
	}
	r.Add(r, one)
	masterSecretKey = bls.NewKyberScalar().SetInt64(r.Int64())

	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()
	masterPublicKey = s.G1().Point().Mul(masterSecretKey, PointG)

	return masterSecretKey, masterPublicKey
}

func GenerateShares(numberOfShares, threshold uint32) (shares []Share, MPK kyber.Point, commits Commitments, err error) {
	buf := make([]byte, 128)
	groupOrder := bigFromHex("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
	s := bls.NewBLS12381Suite()

	_, err = rand.Read(buf)
	if err != nil {
		return nil, nil, nil, err
	}
	secretVal := buf
	masterSecretKey, _ := h3(s, secretVal, []byte("msg"))
	MPK = s.G1().Point().Mul(masterSecretKey, s.G1().Point().Base())
	polynomial, err := createRandomPolynomial(threshold, masterSecretKey, groupOrder)
	if err != nil {
		return shares, nil, nil, fmt.Errorf("shares could not be created due to random polynomial generation failing")
	}

	randomPoly := polynomial

	index := make([]kyber.Scalar, numberOfShares)
	value := make([]kyber.Scalar, numberOfShares)

	for i := range index {
		index[i] = bls.NewKyberScalar().SetInt64(int64(i + 1))
		evalPoly := polynomial.eval(index[i])
		value[i] = evalPoly
	}

	shares = make([]Share, numberOfShares)
	for j := range shares {
		shares[j] = Share{Index: index[j], Value: value[j]}
	}
	commits = GenerateCommits(randomPoly)
	return shares, MPK, commits, nil
}

func lagrangeCoefficientFromShares(indexJ kyber.Scalar, shares []Share) kyber.Scalar {
	nominator := bls.NewKyberScalar().SetInt64(int64(1))
	denominator := bls.NewKyberScalar().SetInt64(int64(1))

	for _, share := range shares {
		if share.Index != indexJ {
			nominator.Mul(nominator, share.Index)

			denominator.Mul(denominator, bls.NewKyberScalar().SetInt64(int64(1)).Add(share.Index, bls.NewKyberScalar().SetInt64(int64(1)).Neg(indexJ)))

		}
	}
	return bls.NewKyberScalar().SetInt64(int64(1)).Div(nominator, denominator) // Inverse will panic if denominator is 0
}

func LagrangeCoefficient(suite pairing.Suite, signer uint32, S []uint32) kyber.Scalar {
	nominator := bls.NewKyberScalar()
	temp := bls.NewKyberScalar()
	temp1 := bls.NewKyberScalar()
	nominator.SetInt64(int64(1))
	denominator := bls.NewKyberScalar()
	denominator.SetInt64(int64(1))

	for _, s := range S {
		if s != signer {
			nominator.Mul(nominator, kyber.Scalar.SetInt64(temp, int64(s)))

			denominator.Mul(denominator,
				kyber.Scalar.Sub(temp,
					kyber.Scalar.SetInt64(temp, int64(s)),
					kyber.Scalar.SetInt64(temp1, int64(signer))))

		}
	}

	outScalar := bls.NewKyberScalar()
	kyber.Scalar.Div(outScalar, nominator, denominator)

	return outScalar
}

func RegenerateSecret(threshold uint32, shares []Share) (masterSecretKey kyber.Scalar, err error) {
	if uint32(len(shares)) != threshold {
		return masterSecretKey, fmt.Errorf("not enough shares to reconstruct master secret key")
	}

	masterSecretKey = bls.NewKyberScalar().Zero()

	for _, share := range shares {
		lagrangeCoeff := lagrangeCoefficientFromShares(share.Index, shares)
		product := bls.NewKyberScalar().One()
		masterSecretKey.Add(masterSecretKey, product.Mul(share.Value, lagrangeCoeff))
	}
	return masterSecretKey, nil
}

func GenerateCommits(polynomial PolynomialCoeff) (commits Commitments) {
	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()
	commits = make(Commitments, len(polynomial))

	for i := 0; i < len(polynomial); i++ {
		commits[i] = s.G1().Point().Mul(polynomial[i], PointG)
	}

	return commits
}

func VerifyVSSShare(share Share, commits Commitments) bool {
	s := bls.NewBLS12381Suite()
	PointG := s.G1().Point().Base()

	shareTimesPointG := s.G1().Point().Mul(share.Value, PointG)
	sum := s.G1().Point().Set(commits[0])

	for i := 1; i < len(commits); i++ {
		indexToI := Exp(share.Index, bls.NewKyberScalar().SetInt64(int64(i)))
		product := s.G1().Point().Mul(indexToI, commits[i])
		sum = s.G1().Point().Add(sum, product)
	}

	return shareTimesPointG.Equal(sum)
}
