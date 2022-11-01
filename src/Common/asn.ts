// from https://github.com/indutny/self-signed/blob/gh-pages/lib/asn1.js
// Fedor, you are amazing.
'use strict';

var asn1 = require('asn1.js');

exports.certificate = require('./certificate');

var RSAPublicKey = asn1.define('RSAPublicKey', (data: any) => {
  data.seq().obj(data.key('modulus').int(), data.key('publicExponent').int());
});
exports.RSAPublicKey = RSAPublicKey;

var PublicKey = asn1.define('SubjectPublicKeyInfo', (data: any) => {
  data.seq().obj(data.key('algorithm').use(AlgorithmIdentifier), data.key('subjectPublicKey').bitstr());
});
exports.PublicKey = PublicKey;

var AlgorithmIdentifier = asn1.define('AlgorithmIdentifier', (data: any) => {
  data
    .seq()
    .obj(
      data.key('algorithm').objid(),
      data.key('none').null_().optional(),
      data.key('curve').objid().optional(),
      data.key('params').seq().obj(data.key('p').int(), data.key('q').int(), data.key('g').int()).optional(),
    );
});

exports.DSAparam = asn1.define('DSAparam', (data: any) => {
  data.int();
});
