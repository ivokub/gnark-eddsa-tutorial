package main

import (
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/consensys/gnark-crypto/ecc"
	cryptotwistededwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	cryptohash "github.com/consensys/gnark-crypto/hash"
	cryptoeddsa "github.com/consensys/gnark-crypto/signature/eddsa"
	"github.com/consensys/gnark/backend/groth16"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/frontend/cs/r1cs"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
	"github.com/consensys/gnark/test"
)

// EdDSAVerifCircuit represents a circuit for verifying EdDSA signatures.
type EdDSAVerifCircuit struct {
	// the elliptic curve used for the signature. Needs to be compatible with
	// the curve used for the circuit. This is not part of the witness but a
	// circuit parameter.
	curveID cryptotwistededwards.ID

	// The witness of the circuit is defined as fields of the struct. By
	// default, the witness is private (only the prover knows it), but we can
	// make it public by adding the `gnark:",public"` tag.

	// Public key of the signer.
	PublicKey eddsa.PublicKey `gnark:",public"`
	// Message to verify.
	Message frontend.Variable // message is private, but it has property that it is not zero.
	// Signature of the message by the signer.
	Signature eddsa.Signature `gnark:",public"`
}

// Define defines the implementation of the circuit.
func (c *EdDSAVerifCircuit) Define(api frontend.API) error {
	// we first initialize the elliptic curve group parameters
	curve, err := twistededwards.NewEdCurve(api, c.curveID)
	if err != nil {
		return fmt.Errorf("new twisted edwards curve: %w", err)
	}
	// we initalize the hasher for computing the hash of the message
	hasher, err := mimc.NewMiMC(api)
	if err != nil {
		return fmt.Errorf("new mimc hasher: %w", err)
	}
	// we assert that the message is not zero
	api.AssertIsDifferent(c.Message, 0)
	// we verify the signature
	if err = eddsa.Verify(curve, c.Signature, c.Message, c.PublicKey, &hasher); err != nil {
		return fmt.Errorf("eddsa verify: %w", err)
	}
	return nil
}

// Test that a valid signature for valid message verifies.
func TestValidSignature(t *testing.T) {
	// parameters -- we use twisted edwards curve BN254 and MiMC hash function
	signatureCurve := cryptotwistededwards.BN254
	hasher := cryptohash.MIMC_BN254

	// create new random signer
	signer, err := cryptoeddsa.New(signatureCurve, rand.Reader)
	if err != nil {
		t.Fatal("failed to create signer", err)
	}

	// sign a message "hello world"
	msg := []byte("hello world")
	signature, err := signer.Sign(msg, hasher.New())
	if err != nil {
		t.Fatal("failed to sign message", err)
	}

	// verify the signature natively
	pub := signer.Public()
	checkSig, err := pub.Verify(signature, msg, hasher.New())
	if err != nil {
		t.Fatal("failed to verify signature", err)
	}
	if !checkSig {
		t.Fatal("signature verification failed")
	}

	// prepare circuit for compilation
	circuit := EdDSAVerifCircuit{
		curveID: signatureCurve,
	}
	// prepare witness assignment
	assignment := EdDSAVerifCircuit{
		Message: msg,
	}
	assignment.PublicKey.Assign(signatureCurve, pub.Bytes())
	assignment.Signature.Assign(signatureCurve, signature)

	// run prover and verifier
	sanitySetupProveVerifyHelper(t, &circuit, &assignment, true)
}

// Test that a valid signature for invalid message does not verify.
func TestInvalidMessage(t *testing.T) {
	signatureCurve := cryptotwistededwards.BN254
	hasher := cryptohash.MIMC_BN254
	signer, err := cryptoeddsa.New(signatureCurve, rand.Reader)
	if err != nil {
		t.Fatal("failed to create signer", err)
	}

	msg := []byte{}
	signature, err := signer.Sign(msg, hasher.New())
	if err != nil {
		t.Fatal("failed to sign message", err)
	}

	pub := signer.Public()
	checkSig, err := pub.Verify(signature, msg, hasher.New())
	if err != nil {
		t.Fatal("failed to verify signature", err)
	}
	if !checkSig {
		t.Fatal("signature verification failed")
	}

	circuit := EdDSAVerifCircuit{
		curveID: signatureCurve,
	}
	assignment := EdDSAVerifCircuit{
		Message: msg,
	}
	assignment.PublicKey.Assign(signatureCurve, pub.Bytes())
	assignment.Signature.Assign(signatureCurve, signature)

	sanitySetupProveVerifyHelper(t, &circuit, &assignment, false)
}

// Test that an invalid signature for valid message does not verify.
func TestInvalidSignature(t *testing.T) {
	signatureCurve := cryptotwistededwards.BN254
	hasher := cryptohash.MIMC_BN254
	signer, err := cryptoeddsa.New(signatureCurve, rand.Reader)
	if err != nil {
		t.Fatal("failed to create signer", err)
	}

	msg := []byte("hello world")
	signature, err := signer.Sign(msg, hasher.New())
	if err != nil {
		t.Fatal("failed to sign message", err)
	}

	pub := signer.Public()
	checkSig, err := pub.Verify(signature, msg, hasher.New())
	if err != nil {
		t.Fatal("failed to verify signature", err)
	}
	if !checkSig {
		t.Fatal("signature verification failed")
	}

	circuit := EdDSAVerifCircuit{
		curveID: signatureCurve,
	}
	assignment := EdDSAVerifCircuit{
		Message: msg,
	}
	assignment.PublicKey.Assign(signatureCurve, pub.Bytes())
	assignment.Signature.Assign(signatureCurve, signature)
	// break signature
	assignment.Signature.S = 10

	sanitySetupProveVerifyHelper(t, &circuit, &assignment, false)

}

func sanitySetupProveVerifyHelper(t *testing.T, circuit, assignment frontend.Circuit, shouldSucceed bool) {
	t.Helper()
	// we need to match the curve used in the circuit
	snarkCurve := ecc.BN254

	// if the circuit is expected to succeed, we sanity check without creating a proof
	if shouldSucceed {
		err := test.IsSolved(circuit, assignment, snarkCurve.ScalarField())
		if err != nil {
			t.Fatal("sanity check failed", err)
		}
	}

	// compile the circuit
	ccs, err := frontend.Compile(snarkCurve.ScalarField(), r1cs.NewBuilder, circuit)
	if err != nil {
		t.Fatal("failed to compile circuit", err)
	}

	// setup the groth16 parameters. NB! This is unsafe version for testing, in practice should use MPC methods.
	pk, vk, err := groth16.Setup(ccs)
	if err != nil {
		t.Fatal("failed to setup groth16 parameters", err)
	}

	// create a prover witness vector from the assignment
	wit, err := frontend.NewWitness(assignment, snarkCurve.ScalarField())
	if err != nil {
		t.Fatal("failed to create prover witness", err)
	}

	// create a proof
	proof, err := groth16.Prove(ccs, pk, wit)
	if shouldSucceed {
		if err != nil {
			t.Fatal("failed to prove circuit", err)
		}
	} else {
		if err == nil {
			t.Fatal("expected to fail proving circuit")
		}
		return
	}

	// create the public witness vector from the assignment
	pubwit, err := frontend.NewWitness(assignment, snarkCurve.ScalarField(), frontend.PublicOnly())
	if err != nil {
		t.Fatal("failed to create public witness", err)
	}

	// verify the proof
	err = groth16.Verify(proof, vk, pubwit)
	if (err == nil) != shouldSucceed {
		t.Fatal("verification result does not match expected result")
	}
}
