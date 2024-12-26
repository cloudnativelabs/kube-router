package utils

import (
	"fmt"
	"math"
)

// File is used to handle numerical conversions safely and ensure that there are no overflows

// IntToUInt64 converts an int to a uint16, returns an error if the int is negative or too large
func IntToUInt16(i int) (uint16, error) {
	if i > math.MaxUint16 {
		return 0, fmt.Errorf("value %d is too large to be converted to uint16", i)
	}

	if i < 0 {
		return 0, fmt.Errorf("value %d is negative, cannot be converted to uint16", i)
	}

	return uint16(i), nil
}

// IntToUInt64 converts an int to a uint64, returns an error if the int is negative or too large
func IntToUInt32(i int) (uint32, error) {
	if i > math.MaxUint32 {
		return 0, fmt.Errorf("value %d is too large to be converted to uint32", i)
	}

	if i < 0 {
		return 0, fmt.Errorf("value %d is negative, cannot be converted to uint32", i)
	}

	return uint32(i), nil
}

// Int32ToUInt32 converts an int32 to a uint32, returns an error if the int is negative
func Int32ToUInt32(i int32) (uint32, error) {
	if i < 0 {
		return 0, fmt.Errorf("value %d is negative, cannot be converted to uint32", i)
	}

	return uint32(i), nil
}

// UIntToInt converts a uint to an int, returns an error if the uint is too large
func UIntToInt(i uint) (int, error) {
	if i > math.MaxInt {
		return 0, fmt.Errorf("value %d is too large to be converted to int", i)
	}

	return int(i), nil
}

// UIntToUInt32 converts a uint to a uint32, returns an error if the uint is too large
func UIntToUInt32(i uint) (uint32, error) {
	if i > math.MaxUint32 {
		return 0, fmt.Errorf("value %d is too large to be converted to uint32", i)
	}

	return uint32(i), nil
}

// UInt32ToInt32 converts a uint32 to an int32, returns an error if the uint is too large
func UInt32ToInt32(i uint32) (int32, error) {
	if i > math.MaxInt32 {
		return 0, fmt.Errorf("value %d is too large to be converted to int32", i)
	}

	return int32(i), nil
}
