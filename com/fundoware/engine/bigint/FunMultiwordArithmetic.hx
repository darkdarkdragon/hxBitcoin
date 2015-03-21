/*===========================================================================

hxBitcoin - pure HaXe cryptocurrency & cryptography library
http://hxbitcoin.com

Copyright (c) 2014 Charles H. Batson III

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

===========================================================================*/

package com.fundoware.engine.bigint;

import com.fundoware.engine.exception.FunExceptions;
import com.fundoware.engine.math.FunInteger;
import haxe.ds.Vector;
import haxe.Int32;

@:allow(com.fundoware.engine.bigint)
class FunMultiwordArithmetic
{
	public static function isZero(value : Vector<Int>, length : Int) : Bool
	{
		if (length < 1)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		for (i in 0 ... length)
		{
			if (value.get(i) != 0)
			{
				return false;
			}
		}
		return true;
	}

	public static inline function isNegative(value : Vector<Int>, length : Int) : Bool
	{
		return value.get(length - 1) < 0;
	}

	public static function getLengthUnsigned(value : Vector<Int>, length : Int) : Int
	{
		if (length < 1)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		while (--length > 0)
		{
			if (value.get(length) != 0)
			{
				break;
			}
		}
		return length + 1;
	}

	/**
		Perform unsigned (zero) extension of `input` into `result`.

		`input` and `result` may refer to the same object.
	**/
	public static function extendUnsigned(result : Vector<Int>, resultLength : Int, input : Vector<Int>, inputLength : Int) : Void
	{
		if (input == result)
		{
			if (resultLength > inputLength)
			{
				for (i in inputLength ... resultLength)
				{
					result.set(i, 0);
				}
			}
		}
		else
		{
			if (resultLength > inputLength)
			{
				copy(result, input, inputLength);
				for (i in inputLength ... resultLength)
				{
					result.set(i, 0);
				}
			}
			else
			{
				copy(result, input, resultLength);
			}
		}
	}

	/**
		Perform the unary negation of big integer `operand` and put
		the result into big integer `result`.

		Returns `true` if the operation overflowed; `false`
		otherwise.

		Ok for `result` and `operand` to be the same object.
	**/
	public static function negate(result : Vector<Int>, operand : Vector<Int>, length : Int) : Bool
	{
		var c : Int32 = 1;
		var x : Int32 = 0;
		var z : Int32 = 0;
		for (i in 0 ... length)
		{
			x = ~operand.get(i);
			z = x + c;
			result.set(i, z);
			c = (x & ~z) >>> 31;	// "Hacker's Delight" p. 38
		}
		// detect overflow; intuitively, this can only occur for inputs of 2 ^ (32 * N - 1).
		return (~x & z) < 0;
	}

	/**
		Add big integer `operand2` to big integer `operand1` and put
		the result into big integer `result`.

		Ok for `result`, `operand1`, and `operand2` to be the same object.

		Returns the "carry" value of either 0 or 1.
	**/
	public static function add(result : Vector<Int>, operand1 : Vector<Int>, operand2 : Vector<Int>, length : Int) : Int
	{
		if ((length < 1) || (result.length < length) || (operand1.length < length) || (operand2.length < length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		var c : Int32 = 0;
		var x : Int32 = 0, y : Int32 = 0, z : Int32 = 0;
		for (i in 0 ... length)
		{
			x = operand1.get(i);
			y = operand2.get(i);
			z = x + y + c;
			result.set(i, z);
			c = ((x & y) | ((x | y) & ~z)) >>> 31;	// "Hacker's Delight" p. 38
		}
		return c;
	}

	/**
		Subtract big integer `operand2` from big integer `operand1`
		and put the result into big integer `result`.

		Ok for `result`, `operand1`, and `operand2` to be the same object.

		Returns the "borrow" value of either 0 or 1.
	**/
	public static function subtract(result : Vector<Int>, operand1 : Vector<Int>, operand2 : Vector<Int>, length : Int) : Int
	{
		if ((length < 1) || (result.length < length) || (operand1.length < length) || (operand2.length < length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		var c : Int32 = 0;
		var x : Int32 = 0, y : Int32 = 0, z : Int32 = 0;
		for (i in 0 ... length)
		{
			x = operand1.get(i);
			y = operand2.get(i);
			z = x - y - c;
			result.set(i, z);
			c = ((~x & y) | (~(x ^ y) & z)) >>> 31;	// "Hacker's Delight" p. 38
		}
		return c;
	}

	/**
		Multiply `operand1` by `operand2`, where both are unsigned,
		and put the result into `result`.

		`result` must have length >= `operand1Length` + 1.

		`result` may not refer the same object as either `operand1`
		or `operand2`; however, `operand1` and `operand2` may be the
		same object.
	**/
	public static function multiplyIntUnsigned(result : Vector<Int>, operand1 : Vector<Int>, operand1Length : Int, operand2 : Int) : Void
	{
		// TODO: Optimize.
		var op2 = new Vector<Int>(1);
		op2.set(0, operand2);
		multiplyUnsigned(result, operand1, operand1Length, op2, 1);
	}

	/**
		Multiply `operand1` by `operand2`, where both are unsigned,
		and put the result into `result`.

		`result` must have length >= `operand1Length` +
		`operand2Length`.

		`result` may not refer the same object as either `operand1`
		or `operand2`; however, `operand1` and `operand2` may be the
		same object.
	**/
	public static function multiplyUnsigned(result : Vector<Int>, operand1 : Vector<Int>, operand1Length : Int, operand2 : Vector<Int>, operand2Length : Int) : Void
	{
		// Implements Figure 8-1 (p. 172) from "Hacker's Delight", Second Edition; Henry S. Warren, Jr.; 2013.

		if ((operand1 == result) || (operand2 == result))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if ((operand1Length < 1) || (operand2Length < 1))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if ((operand1.length < operand1Length) || (operand2.length < operand2Length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}

		var resultSize : Int = operand1Length + operand2Length;
		if (result.length < resultSize)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		setZero(result, resultSize);

		if (isZero(operand1, operand1Length) || isZero(operand2, operand2Length))
		{
			return;
		}

		var b : Int32, k : Int32, t : Int32;
		var u : Int32, v : Int32, w : Int32;
		var m : Int32 = operand1Length << 1;
		var n : Int32 = operand2Length << 1;

		for (j in 0 ... n)
		{
			v = getShort(operand2, j);
			k = 0;
			for (i in 0 ... m)
			{
				u = getShort(operand1, i);
				w = getShort(result, i + j);
				t = u * v + w + k;
				setShort(result, i + j, t);
				k = t >>> 16;
			}
			setShort(result, j + m, k);
		}
	}

	public static inline function getDivisionQuotientLengthUnsigned(dividendLength : Int, divisorLength : Int) : Int
	{
		return FunInteger.max(dividendLength - divisorLength + 1, 1);
	}

	/**
		Divide `dividend` by `divisor`, where both are unsigned.
		The quotient of the division is put into `quotientOut`;
		the remainder is the return value.

		`quotientOut` must have length >= `dividendLength`.

		`quotientOut` may refer to `dividend`.

		`work` must not refer to any of the inputs, and must have
		length >= `dividendLength` + 2.

		`dividend` is not modified, unless it refers to `quotientOut`.

		The results are unspecified if `divisor` is negative.
	**/
	public static function divideIntUnsigned(dividend : Vector<Int>, dividendLength : Int, divisor : Int, quotientOut : Vector<Int>, work : Vector<Int>) : Int
	{
		// TODO: Consider optimizing this case.
		var remainder = new Vector<Int>(1);
		var vDivisor =  new Vector<Int>(1);
		vDivisor.set(0, divisor);
		divideUnsigned(dividend, dividendLength, vDivisor, 1, quotientOut, remainder, work);
		return remainder.get(0);
	}

	/**
		Divide `dividend` by `divisor`, where both are unsigned.
		The quotient of the division is put into `quotientOut`;
		the remainder is put into `remainderOut`.

		`divisor` must not have any leading zeros.

		`quotientOut` must have length >= `dividendLength` -
		`divisorLength` + 1.

		`remainderOut` may be `null` if the remainder value is not
		needed. If supplied, it must be of length >= `divisorLength`.

		`quotientOut` and `remainderOut` must not refer to the same
		object; but either may refer to the inputs.

		`dividend` and `divisor` may refer to the same object.

		`work` must not refer to any of the inputs, and must have
		length >= `dividendLength` + `divisorLength` + 1.

		`dividend` and `divisor` are not modified, unless they
		reference one of the outputs.
	**/
	public static function divideUnsigned(dividend : Vector<Int>, dividendLength : Int, divisor : Vector<Int>, divisorLength : Int, quotientOut : Vector<Int>, remainderOut : Vector<Int>, work : Vector<Int>) : Void
	{
		if ((quotientOut == null) || (work == null) || (quotientOut == remainderOut))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if ((work == dividend) || (work == divisor) || (work == quotientOut) || (work == remainderOut))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if ((divisorLength < 1) || (dividendLength < 1))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}

		var quotientLength : Int = getDivisionQuotientLengthUnsigned(dividendLength, divisorLength);
		if (quotientOut.length < quotientLength)
		{
			// quotient storage too small
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if ((remainderOut != null) && (remainderOut.length < divisorLength))
		{
			// remainder storage too small
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (work.length < dividendLength + divisorLength + 1)
		{
			// quotient storage too small
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}

		// special cases
		var dh : Int = divisor.get(divisorLength - 1);
		if (divisorLength < 2)
		{
			switch (dh)
			{
				case 0:
					throw FunExceptions.FUN_DIVISION_BY_ZERO;
				case 1:
					copy(quotientOut, dividend, dividendLength);	// quotientLength == dividendLength
					if (remainderOut != null)
					{
						setZero(remainderOut, divisorLength);
					}
					return;
			}
		}
		else if (dh == 0)
		{
			// leading zero
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}

		// trim leading zeros
		/*while ((dividendLength > 1) && (dividend.get(dividendLength - 1) == 0))
		{
			--dividendLength;
		}*/

		if (dividendLength < 2)
		{
			switch (dividend.get(0))
			{
				case 0:
					setZero(quotientOut, quotientLength);
					if (remainderOut != null)
					{
						setZero(remainderOut, divisorLength);
					}
					return;
			}
		}

		// if dividend is shorter than divisor
		if (dividendLength < divisorLength)
		{
			if (remainderOut != null)
			{
				copy(remainderOut, dividend, dividendLength);
				for (i in dividendLength ... divisorLength)
				{
					remainderOut.set(i, 0);
				}
			}
			setZero(quotientOut, quotientLength);
			return;
		}

		// TODO: Handle special case of dividend < divisor.

		// Based on Figure 9-1 (p. 185) from "Hacker's Delight", Second Edition; Henry S. Warren, Jr.; 2013.

		var j : Int32, k : Int32, t : Int32;
		var m : Int32 = dividendLength << 1;
		var un : Int32 = divisorLength << 1;
		var n : Int32 = un;
		if (getShort(divisor, n - 1) == 0)
		{
			--n;
		}

		// Take care of the case of a single-digit divisor here.
		if (n == 1)
		{
			var v0 : Int32 = divisor.get(0);
			if (quotientOut != dividend)
			{
				setZero(quotientOut, quotientLength);
			}
			var uj : Int32;
			k = 0;
			j = m;
			while (--j >= 0)
			{
				uj = getShort(dividend, j);
				t = FunInteger.u32divu16((k << 16) + uj, v0);
				setShort(quotientOut, j, t);
				k = (k << 16) + uj - t * v0;
			}
			if (remainderOut != null)
			{
				setFromIntUnsigned(remainderOut, divisorLength, k);
			}
			return;
		}

		// vn is work[0] through work[divisor.m_count - 1] or shorts [0, n)
		// un is work[divisor.m_count] through work[dividend.m_count + divisor.m_count] or shorts [n, n + m]

		var s : Int32 = FunInteger.nlz(getShort(divisor, n - 1)) - 16;		// 0 <= s < 16
		if (s > 0)
		{
			_lsl32x(work, 0, divisor, divisorLength, s);
			_lsl32x(work, divisorLength, dividend, dividendLength, s);
		}
		else
		{
			Vector.blit(divisor, 0, work, 0, divisorLength);
			Vector.blit(dividend, 0, work, divisorLength, dividendLength);
			work.set(divisorLength + dividendLength, 0);
		}

		setZero(quotientOut, quotientLength);

		// Main loop.
		var qhat : Int32, rhat : Int32, p : Int32, t : Int32;
		var vn : Int32 = getShort(work, n - 1);
		j = m - n + 1;
		while (--j >= 0)
		{
			// Compute estimate qhat of q[j]
			t = (getShort(work, j + n + un) << 16) + getShort(work, j + n + un - 1);
			qhat = FunInteger.u32divu16(t, vn);
			rhat = t - qhat * vn;
            //trace('t: $t, qhat: $qhat, rhat: $rhat');
			while ((qhat >= 65536) || FunInteger.u32gtu32(qhat * getShort(work, n - 2), (rhat << 16) + getShort(work, j + n + un - 2)))
			{
				qhat -= 1;
				rhat += vn;
				if (rhat >= 65536)
				{
					break;
				}
			}

			// Multiply and subtract
			k = 0;
			for (i in 0 ... n)
			{
				p = qhat * getShort(work, i);
				t = getShort(work, i + j + un) - k - (p & 0xffff);
				setShort(work, i + j + un, t);
				k = (p >>> 16) - (t >> 16);
			}
			t = getShort(work, j + n + un) - k;
			setShort(work, j + n + un, t);

			// Store quotient digit.
			// If we subtracted too much, add back.
			if (t >= 0)
			{
				setShort(quotientOut, j, qhat);
			}
			else
			{
				setShort(quotientOut, j, qhat - 1);
				k = 0;
				for (i in 0 ... n)
				{
					t = getShort(work, i + j + un) + getShort(work, i) + k;
					setShort(work, i + j + un, t);
					k = t >> 16;
				}
				t = getShort(work, j + n + un) + k;
				setShort(work, j + n + un, t);
			}
		}

		// If the caller wants the remainder, unnormalize it and pass back.
		if (remainderOut != null)
		{
			if (s > 0)
			{
				_lsr32(remainderOut, work, divisorLength, divisorLength, s);
			}
			else
			{
				Vector.blit(work, divisorLength, remainderOut, 0, divisorLength);
			}
		}
	}

	/**
		Shift multiword integer `input` right by `shift` binary
		places and store the result in `result`, with the high bit
		duplicated for bits inserted from the left.

		`shift` must meet the critera 0 <= `shift` < 32.

		`result` and `input` may be the same object.
	**/
	public static function arithmeticShiftRight(result : Vector<Int>, input : Vector<Int>, length : Int, shift : Int) : Void
	{
		if ((length < 1) || (result.length < length) || (input.length < length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (shift < 0)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		else if (shift == 0)
		{
			if (input != result)
			{
				Vector.blit(input, 0, result, 0, length);
			}
		}
		else if (shift < 32)
		{
			_asr32(result, input, length, 0, shift);
		}
		else
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
	}

	/**
		Shift multiword integer `input` right by `shift` binary
		places and store the result in `result`, with zeros inserted
		from the left.

		`shift` must meet the critera 0 <= `shift` < 32.

		`result` and `input` may be the same object.
	**/
	public static function logicalShiftRight(result : Vector<Int>, input : Vector<Int>, length : Int, shift : Int) : Void
	{
		if ((length < 1) || (result.length < length) || (input.length < length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (shift < 0)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		else if (shift == 0)
		{
			if (input != result)
			{
				Vector.blit(input, 0, result, 0, length);
			}
		}
		else if (shift < 32)
		{
			_lsr32(result, input, length, 0, shift);
		}
		else
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
	}

	/**
		Shift multiword integer `input` left by `shift` binary
		places and store the result in `result`, with zeros inserted
		from the right.

		`shift` must meet the critera 0 <= `shift` < 32.

		`result` and `input` may be the same object.
	**/
	public static function shiftLeft(result : Vector<Int>, input : Vector<Int>, length : Int, shift : Int) : Void
	{
		if ((length < 1) || (result.length < length) || (input.length < length))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (shift < 0)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		else if (shift == 0)
		{
			if (input != result)
			{
				Vector.blit(input, 0, result, 0, length);
			}
		}
		else if (shift < 32)
		{
			_lsl32(result, 0, input, length, shift);
		}
		else
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
	}

	/**
		Compare two signed multiword integers.

		Returns -1 if `a < b`; otherwise
		returns 1 if `a > b`; otherwise
		returns 0 (`a == b`).
	**/
	public static function compareSigned(a : Vector<Int>, b : Vector<Int>, length : Int) : Int
	{
		if (a != b)
		{
			var ah : Int32 = a.get(length - 1);
			var bh : Int32 = b.get(length - 1);
			if ((ah ^ bh) < 0)
			{
				// differing signs
				return (ah >> 30) | 1;
			}
			return compareUnsigned(a, b, length);
		}
		return 0;
	}

	/**
		Compare two unsigned multiword integers.

		Returns -1 if `a < b`; otherwise
		returns 1 if `a > b`; otherwise
		returns 0 (`a == b`).
	**/
	public static function compareUnsigned(a : Vector<Int>, b : Vector<Int>, length : Int) : Int
	{
		if (a != b)
		{
			var an : Int32, bn : Int32, d : Int32;
			var x : Int32 = -2147483648;
			while (--length >= 0)
			{
				an = a.get(length) + x;
				bn = b.get(length) + x;
				if (an > bn) return  1;
				if (an < bn) return -1;
			}
		}
		return 0;
	}

	public static function setZero(dest : Vector<Int>, length : Int) : Void
	{
		if (dest.length < length)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		for (i in 0 ... length)
		{
			dest.set(i, 0);
		}
	}

	public static function setFromIntUnsigned(dest : Vector<Int>, length : Int, value : Int) : Void
	{
		if (dest.length < length)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		dest.set(0, value);
		for (i in 1 ... length)
		{
			dest.set(i, 0);
		}
	}

	public static function setFromHexUnsigned(dest : Vector<Int>, length : Int, value : String) : Bool
	{
		if ((value == null) || (dest == null))
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (dest.length < length)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		var index = value.length;
		if (index <= 0)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		if (length < 1)
		{
			return false;
		}
		var c : Int32;
		var start : Int32 = 0;
		while (start < index)
		{
			c = value.charCodeAt(start);
			if ((c != 48) && (c != 32))
			{
				break;
			}
			++start;
		}
		var pos : Int32 = 0;
		var bit : Int32 = 0;
		var acc : Int32 = 0;
		while (index > start)
		{
			c = value.charCodeAt(--index);
			if ((48 <= c) && (c <= 57))
			{
				c -= 48;
			}
			else if ((65 <= c) && (c <= 70))
			{
				c -= 55;
			}
			else if ((97 <= c) && (c <= 102))
			{
				c -= 87;
			}
			else if (c == 32)
			{
				continue;
			}
			else
			{
				throw FunExceptions.FUN_INVALID_ARGUMENT;
			}
			acc |= c << bit;
			bit += 4;
			if (bit >= 32)
			{
				if (pos >= length)
				{
					return false;
				}
				dest.set(pos++, acc);
				acc = 0;
				bit = 0;
			}
		}
		if (bit > 0)
		{
			if (pos >= length)
			{
				return false;
			}
			dest.set(pos++, acc);
		}
		for (c in pos ... length)
		{
			dest.set(c, 0);
		}
		return true;
	}

	public static function toHex(input : Vector<Int>, length : Int) : String
	{
		var sb = new StringBuf();
		while (--length >= 0)
		{
			var v = input.get(length);
			for (j in 0 ... 8)
			{
				var c : Int32 = (v >> 28) & 0x0f;
				v <<= 4;
				c = (c < 10) ? (c + 48) : (c - 10 + 97);
				sb.addChar(c);
			}
		}
		return sb.toString();
	}

	/**
		Get the value in decimal form.
	**/
	public static function toDecimalSigned(value : Vector<Int>, length : Int) : String
	{
		var sb = new StringBuf();
		var work = new Vector<Int>(length);
		if (isNegative(value, length))
		{
			negate(work, value, length);
			sb.addChar(45);	// '-'
		}
		else
		{
			copy(work, value, length);
		}
		return _toDecimal(sb, work, length);
	}

	/**
		Get the value in decimal form.
	**/
	public static function toDecimalUnsigned(value : Vector<Int>, length : Int) : String
	{
		var sb = new StringBuf();
		var work = new Vector<Int>(length);
		copy(work, value, length);
		return _toDecimal(sb, work, length);
	}

	public static function copy(dest : Vector<Int>, source : Vector<Int>, length : Int) : Void
	{
		if (dest.length < length)
		{
			throw FunExceptions.FUN_INVALID_ARGUMENT;
		}
		Vector.blit(source, 0, dest, 0, length);
	}

	public static function getBitSigned(value : Vector<Int>, length : Int, index : Int) : Int
	{
		var d : Int32 = index >> 5;
		if (d >= length)
		{
			return value.get(length - 1) >>> 31;
		}
		return (value.get(d) >> (index & 31)) & 1;
	}

	//-----------------------------------------------------------------------
	// Private helpers
	//-----------------------------------------------------------------------

	// assumes 0 < shift < 32
	// ok if output == input
	private static function _lsl32(output : Vector<Int>, outputOffset : Int, input : Vector<Int>, inputSize : Int, shift : Int) : Void
	{
		var x : Int32 = input.get(inputSize - 1);
		var r : Int32 = 32 - shift;
		var y : Int32;
		while (--inputSize > 0)
		{
			y = input.get(inputSize - 1);
			x = (x << shift) | (y >>> r);
			output.set(inputSize + outputOffset, x);
			x = y;
		}
		output.set(outputOffset, x << shift);
	}

	// assumes 0 < shift < 32
	// ok if output == input
	// note this writes inputSize + 1 words to output
	private static function _lsl32x(output : Vector<Int>, outputOffset : Int, input : Vector<Int>, inputSize : Int, shift : Int) : Void
	{
		var x : Int32 = 0;
		var r : Int32 = 32 - shift;
		var y : Int32;
		while (inputSize > 0)
		{
			y = input.get(inputSize - 1);
			x = (x << shift) | (y >>> r);
			output.set(inputSize + outputOffset, x);
			x = y;
			--inputSize;
		}
		output.set(outputOffset, x << shift);
	}

	// assumes 0 < shiftBits < 32
	// assumes shiftDigits < length
	private static function _asr32(result : Vector<Int>, input : Vector<Int>, length : Int, shiftDigits : Int, shiftBits : Int) : Void
	{
		var r : Int32 = 32 - shiftBits;
		var i : Int32 = 0;
		while (i < length - shiftDigits - 1)
		{
			result.set(i, (input.get(i + shiftDigits) >>> shiftBits) | (input.get(i + shiftDigits + 1) << r));
			++i;
		}
		result.set(i, input.get(i + shiftDigits) >> shiftBits);
	}

	// assumes 0 < shift < 32
	// ok if output == input
	private static function _lsr32(output : Vector<Int>, input : Vector<Int>, inputSize : Int, inputOffset : Int, shift : Int) : Void
	{
		var r : Int32 = 32 - shift;
		var i : Int32 = 0;
		while (i < inputSize - 1)
		{
			output.set(i, (input.get(inputOffset + i) >>> shift) | (input.get(inputOffset + i + 1) << r));
			++i;
		}
		output.set(i, input.get(inputOffset + i) >>> shift);
	}

	@:noCompletion
	private static function _toDecimal(sb : StringBuf, value : Vector<Int>, length : Int) : String
	{
		length = getLengthUnsigned(value, length);
		var digits = new Vector<Int>(length * 10);	// it is really log10 2^32 ~= 9.633, but this is close, simple, and never too little
		var work = new Vector<Int>(length + 1 + 1);
		var pos : Int = digits.length;
		var r : Int32;
		do
		{
			r = divideIntUnsigned(value, length, 10, value, work);
			length = getLengthUnsigned(value, length);
			digits.set(--pos, r + 48);
		} while (!isZero(value, length));
		for (i in pos ... digits.length)
		{
			sb.addChar(digits.get(i));
		}
		return sb.toString();
	}

	private static inline function getShort(v : Vector<Int>, n : Int) : Int
	{
		return (v.get(n >> 1) >> ((n & 1) << 4)) & 0xffff;
	}

	private static inline function setShort(a : Vector<Int>, n : Int, v : Int) : Void
	{
		var s : Int32 = (n & 1) << 4;
		var t : Int32 = a.get(n >> 1) & (~0xffff >>> s);
		a.set(n >> 1, t | ((v & 0xffff) << s));
	}
}
