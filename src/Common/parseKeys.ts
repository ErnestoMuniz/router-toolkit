export default function parseKeys(buffer: any) {
  var stripped = fixProc(buffer);

  var type = stripped.tag;
  var data = stripped.data;
  var subtype, ndata;
  switch (type) {
    case 'PUBLIC KEY':
      if (!ndata) {
        ndata = asn1.PublicKey.decode(data, 'der');
      }
      subtype = ndata.algorithm.algorithm.join('.');
      switch (subtype) {
        case '1.2.840.113549.1.1.1':
          return asn1.RSAPublicKey.decode(ndata.subjectPublicKey.data, 'der');
        case '1.2.840.10045.2.1':
          ndata.subjectPrivateKey = ndata.subjectPublicKey;
          return {
            type: 'ec',
            data: ndata,
          };
        case '1.2.840.10040.4.1':
          ndata.algorithm.params.pub_key = asn1.DSAparam.decode(ndata.subjectPublicKey.data, 'der');
          return {
            type: 'dsa',
            data: ndata.algorithm.params,
          };
        default:
          throw new Error('unknown key id ' + subtype);
      }
    default:
      throw new Error('unknown key type ' + type);
  }
}

var findProc =
  /Proc-Type: 4,ENCRYPTED[\n\r]+DEK-Info: AES-((?:128)|(?:192)|(?:256))-CBC,([0-9A-H]+)[\n\r]+([0-9A-z\n\r+/=]+)[\n\r]+/m;
var startRegex = /^-----BEGIN ((?:.*? KEY)|CERTIFICATE)-----/m;
var fullRegex = /^-----BEGIN ((?:.*? KEY)|CERTIFICATE)-----([0-9A-z\n\r+/=]+)-----END \1-----$/m;

function fixProc(okey: any) {
  var key = okey.toString();
  var decrypted;
  var match2 = key.match(fullRegex);
  decrypted = Buffer.from(match2[2].replace(/[\r\n]/g, ''), 'base64');
  var tag = key.match(startRegex)[1];
  return {
    tag: tag,
    data: decrypted,
  };
}