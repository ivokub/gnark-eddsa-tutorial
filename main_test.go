package main

import (
	"fmt"

	cryptotwistededwards "github.com/consensys/gnark-crypto/ecc/twistededwards"
	"github.com/consensys/gnark/frontend"
	"github.com/consensys/gnark/std/algebra/native/twistededwards"
	"github.com/consensys/gnark/std/hash/mimc"
	"github.com/consensys/gnark/std/signature/eddsa"
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

