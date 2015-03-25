package com.fundoware.engine.crypto.util;

/*===========================================================================

Ported from https://crypto.stanford.edu/sjcl/ by Ivan Tivonenko

Copyright (c) 2015 Ivan Tivonenko

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

import haxe.io.Bytes;
import haxe.io.BytesData;

class CCM
{
	public static function encrypt(src : Bytes, blockSize : Int, decrypt : Bytes->Int->Bytes->Int->Void, encrypt : Bytes->Int->Bytes->Int->Void, ivIn : Bytes, adata : Bytes, ?tlen: Int = 64) : Bytes
	{
        var tblen = Math.floor(tlen / 8);
		var ivLength : Int = ivIn.length;
		if (ivLength < 7) {
			throw "initial vector too small";
		}

		var iv = ivIn.getData();
        var ol = src.length * 8;
        // compute the length of the length
        var L = 2;
        while ( L < 4 && (ol >>> 8 * L) != 0 ) {
            L++;
        }

        if (L < 15 - ivLength) {
            L = 15 - ivLength;
        }
        var toClampIv = (15 - L);
        ivIn = ivIn.sub(0, toClampIv);

        // compute the tag
        var tag = computeTag(encrypt, src, src.length, ivIn, adata, tlen, L, blockSize);

        // encrypt
        var out = ctrMode(decrypt, encrypt, src, ivIn, tag, tlen, L, blockSize);
        var outData = Bytes.alloc(out.data.length + out.tag.length);
        outData.blit(0, out.data, 0, out.data.length);
        outData.blit(out.data.length, out.tag, 0, out.tag.length);

        return outData;
	}

	public static function decrypt(src : Bytes, blockSize : Int, decrypt : Bytes->Int->Bytes->Int->Void, encrypt : Bytes->Int->Bytes->Int->Void, ivIn : Bytes, adata : Bytes, ?tlen: Int = 64) : Bytes
	{
        /// the desired tag length, in bits.
        var tblen = Math.floor(tlen / 8);
		var ivLength : Int = ivIn.length;
		if (ivLength < 7) {
			throw "initial vector too small";
		}
		var iv = ivIn.getData();
        var ol = src.length * 8;
        var srcToDec = src.sub(0, src.length - tblen);

        ol = src.length - tblen;
        var tag = src.sub(src.length - tblen, tblen);

        // compute the length of the length
        var L = 2;
        while ( L < 4 && (ol >>> 8 * L) != 0 ) {
            L++;
        }

        if (L < 15 - ivLength) {
            L = 15 - ivLength;
        }
        var toClampIv = (15 - L);
        ivIn = ivIn.sub(0, toClampIv);
        var decRes = ctrMode(decrypt, encrypt, srcToDec, ivIn, tag, tlen, L, blockSize);
        if (decRes == null || decRes.data == null) {
            return null;
        }

        // check the tag
        var tag2 = computeTag(encrypt, decRes.data, srcToDec.length, ivIn, adata, tlen, L, blockSize);

        if (tag2.compare(decRes.tag) != 0) {
            throw "ccm: tag doesn't match";
        }

        if (decRes != null && decRes.data != null) {
            return decRes.data;
        }
        return null;

	}

    /* Compute the (unencrypted) authentication tag, according to the CCM specification
     * @param {Object} prf The pseudorandom function.
     * @param {bitArray} plaintext The plaintext data.
     * @param {bitArray} iv The initialization value.
     * @param {bitArray} adata The authenticated data.
     * @param {Number} tlen the desired tag length, in bits.
     * @return {bitArray} The tag, but not yet encrypted.
     * @private
     */
    private static  function computeTag(encrypt : Bytes->Int->Bytes->Int->Void, plaintext: Bytes, decodeLength: Int, iv: Bytes, adata: Bytes, tlen: Int, L: Int, blockSize: Int): Bytes {
        tlen = Math.floor(tlen / 8);

        // check tag length and message length
        if ( (tlen % 2 != 0) || tlen < 4 || tlen > 16) {
            throw "ccm: invalid tag length";
        }

        if (adata != null && (adata.length > 4294967295 || plaintext.length > 4294967295)) {
            // I don't want to deal with extracting high words from doubles.
            throw "ccm: can't deal with 4GiB or more data";
        }

        var mac = Bytes.alloc(blockSize);
        mac.fill(0, blockSize, 0);
        mac.set(0, (adata != null && adata.length > 0 ? 1 << 6 : 0) | (tlen - 2) << 2 | L - 1);
        // mac the iv and length
        mac.blit(1, iv, 0, iv.length);
        var mac3 = mac.get(15) | (mac.get(14) << 8) | (mac.get(13) << 16) | (mac.get(12) << 24);
        mac3 |= decodeLength;
		mac.set(15, mac3);
		mac.set(14, mac3 >> 8);
		mac.set(13, mac3 >> 16);
		mac.set(12, mac3 >>> 24);

        encrypt(mac, 0, mac, 0);

        if (adata != null && adata.length > 0) {
            // mac the associated data.  start with its length...
            var tmp = adata.length | 0;
            var macData = null;
            var blitPos = 0;
            if (tmp <= 0xFEFF) {
                macData = Bytes.alloc(adata.length + 2);
                //macData = [w.partial(16, tmp)];
                macData.set(0, tmp >> 8);
                macData.set(1, tmp);
                blitPos = 2;
            } else if (tmp <= 0xFFFFFFFF) {
                macData = Bytes.alloc(adata.length + 4);
                //macData = w.concat([w.partial(16,0xFFFE)], [tmp]);
                macData.set(0, 0xFF);
                macData.set(1, 0xFE);
                macData.set(2, tmp >> 8);
                macData.set(3, tmp);
                blitPos = 4;
            } // else ...
            if (macData == null) {
                throw "too long adata";
            }

            // mac the data itself
            macData.blit(blitPos, adata, 0, adata.length);
            var i = 0;
            while (i < macData.length) {
                for (j in 0...blockSize) {
                    mac.set(j, mac.get(j) ^ (i < macData.length ? macData.get(i) : 0));
                    i++;
                }
                encrypt(mac, 0, mac, 0);
            }
        }

        // mac the plaintext
        var i = 0;
        while (i < decodeLength) {
            for (j in 0...blockSize) {
                mac.set(j, mac.get(j) ^ (i < decodeLength ? plaintext.get(i) : 0));
                i++;
            }
            encrypt(mac, 0, mac, 0);
        }
        if (mac.length > tlen) {
            return mac.sub(0, tlen);
        }
        return mac;
    }



    /** CCM CTR mode.
       * Encrypt or decrypt data and tag with the prf in CCM-style CTR mode.
       * May mutate its arguments.
       * @param {Object} prf The PRF.
       * @param {bitArray} data The data to be encrypted or decrypted.
       * @param {bitArray} iv The initialization vector.
       * @param {bitArray} tag The authentication tag.
       * @param {Number} tlen The length of th etag, in bits.
       * @param {Number} L The CCM L value.
       * @return {Object} An object with data and tag, the en/decryption of data and tag values.
       * @private
       */
    //_ctrMode: function(prf, data, iv, tag, tlen, L)
    private static function ctrMode(decrypt : Bytes->Int->Bytes->Int->Void, encrypt : Bytes->Int->Bytes->Int->Void, data: Bytes, iv: Bytes, tag: Bytes, tlen: Int, L: Int, blockSize: Int) {
        var l = data.length;

        // start the ctr
        var ctrLen = iv.length + 1 < blockSize ? blockSize : iv.length + 1;
        var ctr = Bytes.alloc(ctrLen);
        ctr.fill(0, ctrLen, 0);
        ctr.set(0, L - 1);
        ctr.blit(1, iv, 0, iv.length);
        var ctrCrypt = Bytes.alloc(blockSize);
        encrypt(ctr, 0, ctrCrypt, 0);
        var tlenb = Math.floor(tlen / 8);
        // en/decrypt the tag
        var tagEnc = Bytes.alloc(tlenb);
        for (i in 0...tlenb) {
            tagEnc.set(i, tag.get(i) ^ ctrCrypt.get(i));
        }

        // en/decrypt the data
        if (l == 0) {
            return { tag: tagEnc, data: null };
        }

        var outData = Bytes.alloc(data.length);
        var c1 = ctr.getInt32(12);
        var i = 0;
        do {
            incInArr(ctr, blockSize - 1);
            encrypt(ctr, 0, ctrCrypt, 0);
            for (j in 0...ctrCrypt.length) {
                outData.set(i, data.get(i) ^ ctrCrypt.get(j));
                i++;
            }
        } while (i < l);
        return { tag: tagEnc, data: outData };
    }

    private static inline function incInArr(data: Bytes, pos: Int) {
        var v = data.get(pos);
        v++;
        data.set(pos, v & 0xff);
        if (v > 0xff && pos > 0) {
            incInArr(data, pos - 1);
        }
    }

}

