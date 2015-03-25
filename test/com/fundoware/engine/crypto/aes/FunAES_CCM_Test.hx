/*===========================================================================

hxBitcoin - pure HaXe cryptocurrency & cryptography library
http://hxbitcoin.com

Ported from https://crypto.stanford.edu/sjcl/

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

package com.fundoware.engine.crypto.aes;

import com.fundoware.engine.core.FunUtils;
import com.fundoware.engine.test.FunTestCase;
import haxe.io.Bytes;
import haxe.io.BytesData;

class FunAES_CCM_Test extends FunTestCase
{

	public function testCCM() : Void
	{
        var i = 0;
        for (vector in FunAES_CCM_Test_vectors.vectors) {
            var aes = new FunAES(FunUtils.hexToBytes(vector.key));
            var len = 32 * vector.key.length;
            // Convert from strings
            var iv = FunUtils.hexToBytes(vector.iv);
            var ad = FunUtils.hexToBytes(vector.adata);
            var pt = FunUtils.hexToBytes(vector.pt);
            var ct = FunUtils.hexToBytes(vector.ct + vector.tag);
            var tlen = vector.tag.length * 4;
            var enc = aes.encryptCCM(pt, iv, ad, tlen);
            if (enc == null || compareBytes(enc, ct) != 0) {
                trace('error in aes-${len}-ccm-encrypt #$i (${vector.tag}) (compare: ${enc.compare(ct)})');
                trace('enc: ' + enc.toHex());
                trace('ct:  ' + ct.toHex());
            }
            assertTrue(enc != null && compareBytes(enc, ct) == 0);

            var dec = aes.decryptCCM(ct, iv, ad, tlen);
            if (dec == null || compareBytes(dec, pt) != 0) {
                trace('error in aes-${len}-ccm-decrypt #$i (${vector.tag}) (compare: ${dec.compare(pt)})');
                trace('dec: ' + dec.toHex());
                trace('pt:  ' + pt.toHex());
            }
            assertTrue(dec != null && compareBytes(dec, pt) == 0);
            i++;
        }
	}

    private static function compareBytes(bs1: Bytes, bs2: Bytes): Int {
        #if cpp
		var b1 = bs1.getData();
		var b2 = bs2.getData();
		var len = (bs1.length < bs2.length) ? bs1.length : bs2.length;
		for ( i in 0...len )
			if( b1[i] != b2[i] )
				return untyped b1[i] - untyped b2[i];
		return bs1.length - bs2.length;
        #else
        return bs1.compare(bs2);
        #end
    }

}
