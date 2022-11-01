import parseKeys from './parseKeys';
var crt = require('browserify-rsa');
var BN = require('bn.js');
var randomBytes = require('randombytes');
var Buffer = require('safe-buffer').Buffer;

function withPublic(paddedMsg: any, key: any) {
  return Buffer.from(paddedMsg.toRed(BN.mont(key.modulus)).redPow(new BN(key.publicExponent)).fromRed().toArray());
}

export default function publicEncrypt(publicKey: any, msg: any, reverse: any) {
  var padding;
  if (publicKey.padding) {
    padding = publicKey.padding;
  } else if (reverse) {
    padding = 1;
  } else {
    padding = 4;
  }
  var key = parseKeys(publicKey);
  var paddedMsg = pkcs1(key, msg, reverse);
  if (reverse) {
    return crt(paddedMsg, key);
  } else {
    return withPublic(paddedMsg, key);
  }
}

function pkcs1(key: any, msg: any, reverse: any) {
  var mLen = msg.length;
  var k = key.modulus.byteLength();
  if (mLen > k - 11) {
    throw new Error('message too long');
  }
  var ps;
  if (reverse) {
    ps = Buffer.alloc(k - mLen - 3, 0xff);
  } else {
    ps = nonZero(k - mLen - 3);
  }
  return new BN(Buffer.concat([Buffer.from([0, reverse ? 1 : 2]), ps, Buffer.alloc(1), msg], k));
}

function nonZero(len: number) {
  var out = Buffer.allocUnsafe(len);
  var i = 0;
  var cache = randomBytes(len * 2);
  var cur = 0;
  var num;
  while (i < len) {
    if (cur === cache.length) {
      cache = randomBytes(len * 2);
      cur = 0;
    }
    num = cache[cur++];
    if (num) {
      out[i++] = num;
    }
  }
  return out;
}
