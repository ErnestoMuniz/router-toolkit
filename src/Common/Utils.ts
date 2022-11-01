import CryptoJS from 'crypto-js';
import publicEncrypt from 'public-encrypt';

/**
 * Converts Hex to String.
 *
 * @param hex - The hex string to convert
 * @returns True UTF-8 converted string
 */
export function hex2a(hex: string) {
  const buf = Buffer.from(hex, 'hex');
  return buf.toString('utf-8');
}

/**
 * Generates a random string of numbers.
 *
 * @param n - The length of the string
 * @returns The random string
 */
export function randomNum(n: number) {
  let t = '';
  for (let i = 0; i < n; i++) {
    t += Math.floor(Math.random() * 10);
  }
  return t;
}

/**
 * Decodes a SSID password.
 *
 * @param src - The encrypted password
 * @param key - The decryption key
 * @returns The decrypted password
 */
export function decodePassword(src: string, key: string) {
  const iv = key.split('').reverse().join('');
  if (src === '') {
    return '';
  }
  const bkey = CryptoJS.SHA256(key);
  const biv = CryptoJS.SHA256(iv);
  const decrypted = CryptoJS.AES.decrypt(src, bkey, {
    iv: biv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.ZeroPadding,
  });
  return decrypted.toString(CryptoJS.enc.Utf8);
}

/**
 * Encodes a string with AES256.
 *
 * @param src - The string to be encrypted
 * @param key - The encryption key
 * @param iv - The IV to use
 * @returns The encrypted password
 */
export function encodePassword(src: string, key: string, iv: string) {
  if (src.length > 0) {
    const bKey = CryptoJS.SHA256(key);
    const bIv = CryptoJS.SHA256(iv);
    const encrypted = CryptoJS.AES.encrypt(src, bKey, {
      iv: bIv,
      mode: CryptoJS.mode.CBC,
      padding: CryptoJS.pad.ZeroPadding,
    });
    const dst = encrypted.toString();
    if (dst !== '' && dst !== 'failed') {
      return dst;
    }
  }
  return src;
}

/**
 * Encodes the string with RSA.
 *
 * @param src - The string to be encrypted
 * @returns The encrypted string
 */
export function asyEncode(src: any) {
  return publicEncrypt(
      Object.assign({
        key: '-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAodPTerkUVCYmv28SOfRV\n7UKHVujx/HjCUTAWy9l0L5H0JV0LfDudTdMNPEKloZsNam3YrtEnq6jqMLJV4ASb\n1d6axmIgJ636wyTUS99gj4BKs6bQSTUSE8h/QkUYv4gEIt3saMS0pZpd90y6+B/9\nhZxZE/RKU8e+zgRqp1/762TB7vcjtjOwXRDEL0w71Jk9i8VUQ59MR1Uj5E8X3WIc\nfYSK5RWBkMhfaTRM6ozS9Bqhi40xlSOb3GBxCmliCifOJNLoO9kFoWgAIw5hkSIb\nGH+4Csop9Uy8VvmmB+B3ubFLN35qIa5OG5+SDXn4L7FeAA5lRiGxRi8tsWrtew8w\nnwIDAQAB\n-----END PUBLIC KEY-----',
        padding: 1,
      }),
      Buffer.from(src),
    )
    .toString('base64');
}

/**
 * Encodes public and private keys.
 *
 * @param key - The encryption key
 * @param iv - The IV to encrypt
 * @returns The encrypted keys
 */
export function encodeKey(key: string, iv: string) {
  return asyEncode(key + '+' + iv);
}

/**
 * Parse and object to query string.
 *
 * @param obj - The object to be parsed
 * @returns The result query string
 */
export function toQS(obj: any) {
  const str = [];
  for (const p in obj)
    if (obj.hasOwnProperty(p)) {
      str.push(encodeURIComponent(p) + '=' + encodeURIComponent(obj[p]));
    }
  return str.join('&');
}
