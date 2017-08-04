package tsm1

import (
	"fmt"

	"github.com/influxdata/influxdb/influxql"
	"github.com/influxdata/influxdb/tsdb"
)

func newLimitIterator(input influxql.Iterator, opt influxql.IteratorOptions) influxql.Iterator {
	switch input := input.(type) {
	case influxql.FloatIterator:
		return newFloatLimitIterator(input, opt)
	case influxql.IntegerIterator:
		return newIntegerLimitIterator(input, opt)
	case influxql.UnsignedIterator:
		return newUnsignedLimitIterator(input, opt)
	case influxql.StringIterator:
		return newStringLimitIterator(input, opt)
	case influxql.BooleanIterator:
		return newBooleanLimitIterator(input, opt)
	default:
		panic(fmt.Sprintf("unsupported limit iterator type: %T", input))
	}
}

type floatCastIntegerCursor struct {
	cursor integerCursor
}

func (c *floatCastIntegerCursor) close() error { return c.cursor.close() }

func (c *floatCastIntegerCursor) next() (t int64, v interface{}) { return c.nextFloat() }

func (c *floatCastIntegerCursor) nextFloat() (int64, float64) {
	t, v := c.cursor.nextInteger()
	return t, float64(v)
}

type floatCastUnsignedCursor struct {
	cursor unsignedCursor
}

func (c *floatCastUnsignedCursor) close() error { return c.cursor.close() }

func (c *floatCastUnsignedCursor) next() (t int64, v interface{}) { return c.nextFloat() }

func (c *floatCastUnsignedCursor) nextFloat() (int64, float64) {
	t, v := c.cursor.nextUnsigned()
	return t, float64(v)
}

type integerCastFloatCursor struct {
	cursor floatCursor
}

func (c *integerCastFloatCursor) close() error { return c.cursor.close() }

func (c *integerCastFloatCursor) next() (t int64, v interface{}) { return c.nextInteger() }

func (c *integerCastFloatCursor) nextInteger() (int64, int64) {
	t, v := c.cursor.nextFloat()
	return t, int64(v)
}

type integerCastUnsignedCursor struct {
	cursor unsignedCursor
}

func (c *integerCastUnsignedCursor) close() error { return c.cursor.close() }

func (c *integerCastUnsignedCursor) next() (t int64, v interface{}) { return c.nextInteger() }

func (c *integerCastUnsignedCursor) nextInteger() (int64, int64) {
	t, v := c.cursor.nextUnsigned()
	return t, int64(v)
}

type unsignedCastFloatCursor struct {
	cursor floatCursor
}

func (c *unsignedCastFloatCursor) close() error { return c.cursor.close() }

func (c *unsignedCastFloatCursor) next() (t int64, v interface{}) { return c.nextUnsigned() }

func (c *unsignedCastFloatCursor) nextUnsigned() (int64, uint64) {
	t, v := c.cursor.nextFloat()
	return t, uint64(v)
}

type unsignedCastIntegerCursor struct {
	cursor integerCursor
}

func (c *unsignedCastIntegerCursor) close() error { return c.cursor.close() }

func (c *unsignedCastIntegerCursor) next() (t int64, v interface{}) { return c.nextUnsigned() }

func (c *unsignedCastIntegerCursor) nextUnsigned() (int64, uint64) {
	t, v := c.cursor.nextInteger()
	return t, uint64(v)
}

// literalValueCursor represents a cursor that always returns a single value.
// It doesn't not have a time value so it can only be used with nextAt().
type literalValueCursor struct {
	value interface{}
}

func (c *literalValueCursor) close() error                   { return nil }
func (c *literalValueCursor) peek() (t int64, v interface{}) { return tsdb.EOF, c.value }
func (c *literalValueCursor) next() (t int64, v interface{}) { return tsdb.EOF, c.value }
func (c *literalValueCursor) nextAt(seek int64) interface{}  { return c.value }

// preallocate and cast to cursorAt to avoid allocations
var (
	nilFloatLiteralValueCursor    cursorAt = &literalValueCursor{value: (*float64)(nil)}
	nilIntegerLiteralValueCursor  cursorAt = &literalValueCursor{value: (*int64)(nil)}
	nilUnsignedLiteralValueCursor cursorAt = &literalValueCursor{value: (*uint64)(nil)}
	nilStringLiteralValueCursor   cursorAt = &literalValueCursor{value: (*string)(nil)}
	nilBooleanLiteralValueCursor  cursorAt = &literalValueCursor{value: (*bool)(nil)}
)
