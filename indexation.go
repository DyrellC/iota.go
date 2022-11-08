package iotago

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/iotaledger/iota.go/v2/ed25519"

	"github.com/iotaledger/hive.go/serializer"
)

const (
	// IndexationPayloadTypeID defines the indexation payload's ID.
	IndexationPayloadTypeID uint32 = 2
	// IndexationBinSerializedMinSize is the minimum size of an Indexation.
	// 	type bytes + index prefix + one char + data length
	IndexationBinSerializedMinSize = serializer.TypeDenotationByteSize + (3 * serializer.UInt16ByteSize) + serializer.OneByte + serializer.UInt32ByteSize
	// IndexationIndexMaxLength defines the max length of the index within an Indexation.
	IndexationIndexMaxLength = 64
	// IndexationIndexMinLength defines the min length of the index within an Indexation.
	IndexationIndexMinLength = 1
	// Length of an ED25519 Signature
	IndexationSignatureLength = ed25519.SignatureSize
	// Length of an Ed25519 PublicKey
	IndexationPublicKeyLength = ed25519.PublicKeySize
)

var (
	// ErrIndexationIndexExceedsMaxSize gets returned when an Indexation's index exceeds IndexationIndexMaxLength.
	ErrIndexationIndexExceedsMaxSize = errors.New("index exceeds max size")
	// ErrIndexationIndexUnderMinSize gets returned when an Indexation's index is under IndexationIndexMinLength.
	ErrIndexationIndexUnderMinSize = errors.New("index is below min size")
	// ErrIndexationPublicKeyBadSize gets returned when an Indexation's public key is not the correct length
	ErrIndexationPublicKeyBadSize = errors.New("public key is not the correct size")
	// ErrIndexationSignatureBadSize gets returned when an Indexation's signature is not the correct length
	ErrIndexationSignatureBadSize = errors.New("signature is not the correct size")
)

// Indexation is a payload which holds an index and associated data.
type Indexation struct {
	// The index to use to index the enclosing message and data.
	Index []byte `json:"index"`
	// PublicKey of the sender of the message
	PublicKey []byte `json:"publicKey"`
	// The Ed25519 signature of the sender
	Signature []byte `json:"signature"`
	// The data within the payload.
	Data []byte `json:"data"`
}

func (u *Indexation) Deserialize(data []byte, deSeriMode serializer.DeSerializationMode) (int, error) {
	return serializer.NewDeserializer(data).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				if err := serializer.CheckMinByteLength(IndexationBinSerializedMinSize, len(data)); err != nil {
					return fmt.Errorf("invalid indexation bytes: %w", err)
				}
				if err := serializer.CheckType(data, IndexationPayloadTypeID); err != nil {
					return fmt.Errorf("unable to deserialize indexation: %w", err)
				}
			}
			return nil
		}).
		Skip(serializer.TypeDenotationByteSize, func(err error) error {
			return fmt.Errorf("unable to skip indexation payload ID during deserialization: %w", err)
		}).
		ReadVariableByteSlice(&u.Index, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to deserialize indexation index: %w", err)
		}, IndexationIndexMaxLength).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.PublicKey) != IndexationPublicKeyLength:
					return fmt.Errorf("unable to deserialize indexation public key (%d): %w", len(u.PublicKey), ErrIndexationPublicKeyBadSize)
				}
			}
			return nil
		}).
		ReadVariableByteSlice(&u.PublicKey, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to deserialize indexation public key: %w", err)
		}).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.Signature) != IndexationSignatureLength:
					return fmt.Errorf("unable to deserialize indexation signature: %w", ErrIndexationSignatureBadSize)
				}
			}
			return nil
		}).
		ReadVariableByteSlice(&u.Signature, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to deserialize indexation signature: %w", err)
		}).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.Index) < IndexationIndexMinLength:
					return fmt.Errorf("unable to deserialize indexation index: %w", ErrIndexationIndexUnderMinSize)
				}
			}
			return nil
		}).
		ReadVariableByteSlice(&u.Data, serializer.SeriLengthPrefixTypeAsUint32, func(err error) error {
			return fmt.Errorf("unable to deserialize indexation data: %w", err)
		}, MessageBinSerializedMaxSize). // obviously can never be that size
		Done()
}

func (u *Indexation) Serialize(deSeriMode serializer.DeSerializationMode) ([]byte, error) {
	return serializer.NewSerializer().
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.Index) > IndexationIndexMaxLength:
					return fmt.Errorf("unable to serialize indexation index: %w", ErrIndexationIndexExceedsMaxSize)
				case len(u.Index) < IndexationIndexMinLength:
					return fmt.Errorf("unable to serialize indexation index: %w", ErrIndexationIndexUnderMinSize)
				}
				// we do not check the length of the data field as in any circumstance
				// the max size it can take up is dependent on how big the enclosing
				// parent object is
			}
			return nil
		}).
		WriteNum(IndexationPayloadTypeID, func(err error) error {
			return fmt.Errorf("unable to serialize indexation payload ID: %w", err)
		}).
		WriteVariableByteSlice(u.Index, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to serialize indexation index: %w", err)
		}).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.PublicKey) != IndexationPublicKeyLength:
					return fmt.Errorf("unable to serialize indexation public key (%d): %w", len(u.PublicKey), ErrIndexationPublicKeyBadSize)
				}
			}
			return nil
		}).
		WriteVariableByteSlice(u.PublicKey, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to serialize indexation public key: %w", err)
		}).
		AbortIf(func(err error) error {
			if deSeriMode.HasMode(serializer.DeSeriModePerformValidation) {
				switch {
				case len(u.Signature) != IndexationSignatureLength:
					return fmt.Errorf("unable to serialize indexation signature: %w", ErrIndexationSignatureBadSize)
				}
			}
			return nil
		}).
		WriteVariableByteSlice(u.Signature, serializer.SeriLengthPrefixTypeAsUint16, func(err error) error {
			return fmt.Errorf("unable to serialize indexation signature: %w", err)
		}).
		WriteVariableByteSlice(u.Data, serializer.SeriLengthPrefixTypeAsUint32, func(err error) error {
			return fmt.Errorf("unable to serialize indexation data: %w", err)
		}).
		Serialize()
}

func (u *Indexation) MarshalJSON() ([]byte, error) {
	jIndexation := &jsonIndexation{}
	jIndexation.Type = int(IndexationPayloadTypeID)
	jIndexation.Index = hex.EncodeToString(u.Index)
	jIndexation.PublicKey = hex.EncodeToString(u.PublicKey)
	jIndexation.Signature = hex.EncodeToString(u.Signature)
	jIndexation.Data = hex.EncodeToString(u.Data)
	return json.Marshal(jIndexation)
}

func (u *Indexation) UnmarshalJSON(bytes []byte) error {
	jIndexation := &jsonIndexation{}
	if err := json.Unmarshal(bytes, jIndexation); err != nil {
		return err
	}
	seri, err := jIndexation.ToSerializable()
	if err != nil {
		return err
	}
	*u = *seri.(*Indexation)
	return nil
}

// jsonIndexation defines the json representation of an Indexation.
type jsonIndexation struct {
	Type      int    `json:"type"`
	Index     string `json:"index"`
	PublicKey string `json:"publicKey"`
	Signature string `json:"signature"`
	Data      string `json:"data"`
}

func (j *jsonIndexation) ToSerializable() (serializer.Serializable, error) {
	indexBytes, err := hex.DecodeString(j.Index)
	if err != nil {
		return nil, fmt.Errorf("unable to decode index from JSON for indexation: %w", err)
	}
	pkBytes, err := hex.DecodeString(j.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("unable to decode public key from JSON for indexation: %w", err)
	}
	sigBytes, err := hex.DecodeString(j.Signature)
	if err != nil {
		return nil, fmt.Errorf("unable to decode signature from JSON for indexation: %w", err)
	}
	dataBytes, err := hex.DecodeString(j.Data)
	if err != nil {
		return nil, fmt.Errorf("unable to decode data from JSON for indexation: %w", err)
	}

	return &Indexation{Index: indexBytes, PublicKey: pkBytes, Signature: sigBytes, Data: dataBytes}, nil
}
