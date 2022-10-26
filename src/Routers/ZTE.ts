import CryptoJS from 'crypto-js';
import axios from 'axios';
import { asyEncode, decodePassword, encodeKey, encodePassword, hex2a, randomNum, toQS } from '../Common/Utils';
import * as convert from 'xml-js';
import Router from '../Common/Router';
import { toVendor } from '@network-utils/vendor-lookup';
export default class ZTE extends Router {
  public time: number;

  constructor(host: string, port: number, username: string, password: string) {
    super(host, port, username, password);
    this.time = Date.now();
  }

  /**
   * Get the authorization cookie.
   *
   * @returns The cookie in a string format.
   */
  private async login() {
    const first = await axios.get(`http://${this.host}:${this.port}/?_type=loginData&_tag=login_token&_=${this.time}`);
    const cookie = (first.headers['set-cookie'] || [''])[0].split(';')[0];
    const loginToken = first.data.split('>')[1].split('<')[0];
    const sessToken = (
      await axios.get(`http://${this.host}:${this.port}/?_type=loginData&_tag=login_entry&_=${this.time}`, {
        headers: {
          cookie,
        },
      })
    ).data.sess_token;
    const result = await axios.request({
      method: 'POST',
      url: `http://${this.host}:${this.port}`,
      params: { _type: 'loginData', _tag: 'login_entry' },
      headers: {
        cookie,
        Accept: 'application/json, text/javascript, */*; q=0.01',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control': 'no-cache',
        Connection: 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        Origin: `http://${this.host}:${this.port}`,
        Pragma: 'no-cache',
        Referer: `http://${this.host}:${this.port}`,
        'User-Agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/106.0.0.0 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
      },
      data: {
        action: 'login',
        Password: CryptoJS.SHA256(this.password + loginToken),
        Username: this.username,
        _sessionTOKEN: sessToken,
      },
    });
    const authCookie = (result.headers['set-cookie'] || [''])[1].split('=')[1].split(';')[0];
    return authCookie;
  }

  /**
   * Get the Router's SSIDs information.
   *
   * @returns An object conaining the JSON data.
   *
   * @example
   * ```ts
   * [
   *   {
   *     enabled: true,
   *     ssid: 'ZTE_2.4G_NKaehT',
   *     authMode: 'PSKAuthentication',
   *     encryption: 'TKIPandAESEncryption',
   *     hidden: false,
   *     passkey: 'HsojahudA',
   *     maxUser: 32
   *   },
   * ]
   * ```
   */
  public async getSSIDs() {
    const authCookie = await this.login();
    const sessToken = hex2a(
      (
        await axios.get(
          `http://${this.host}:${this.port}/?_type=menuView&_tag=wlanBasic&Menu3Location=0&_=${this.time}`,
          {
            headers: {
              Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
            },
          },
        )
      ).data
        .split('_sessionTmpToken = "')[1]
        .split('"')[0]
        .replaceAll('\\x', ''),
    );
    const res = (
      await axios.get(
        `http://${this.host}:${this.port}/?_type=menuData&_tag=wlan_wlansssidconf_lua.lua&_=${this.time}`,
        {
          headers: {
            Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
          },
        },
      )
    ).data;
    const ssids = (convert.xml2js(res, { compact: true }) as any).ajax_response_xml_root.OBJ_WLANAP_ID.Instance.map(
      (instance: any, i: number) => ({
        enabled: Number(instance.ParaValue[2]._text) === 1,
        ssid: instance.ParaValue[13]._text,
        authMode: instance.ParaValue[3]._text,
        encryption: instance.ParaValue[15]._text,
        hidden: Number(instance.ParaValue[11]._text) === 1,
        passkey: decodePassword(
          (convert.xml2js(res, { compact: true }) as any).ajax_response_xml_root.OBJ_WLANPSK_ID.Instance[i].ParaValue[1]
            ._text,
          sessToken,
        ),
        maxUser: Number(instance.ParaValue[10]._text),
      }),
    );
    return ssids;
  }

  /**
   * Get the Router's WLANs information.
   *
   * @returns An object conaining the JSON data.
   *
   * @example
   * ```ts
   * [
   *   {
   *     frequency: '2.4GHz',
   *     protocol: 'b,g,n',
   *     channel: 1,
   *     beaconInterval: 100,
   *     txPower: 100,
   *     band: 'Auto',
   *     enabled: true
   *   }
   * ]
   * ```
   */
  public async getWlans() {
    const authCookie = await this.login();
    const sessToken = hex2a(
      (
        await axios.get(
          `http://${this.host}:${this.port}/?_type=menuView&_tag=wlanBasic&Menu3Location=0&_=${this.time}`,
          {
            headers: {
              Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
            },
          },
        )
      ).data
        .split('_sessionTmpToken = "')[1]
        .split('"')[0]
        .replaceAll('\\x', ''),
    );
    const res = (
      await axios.get(
        `http://${this.host}:${this.port}/?_type=menuData&_tag=wlan_wlanbasicadconf_lua.lua&_=${this.time}`,
        {
          headers: {
            Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
          },
        },
      )
    ).data;
    const wlans = (
      convert.xml2js(res, { compact: true }) as any
    ).ajax_response_xml_root.OBJ_WLANSETTING_ID.Instance.map((instance: any, i: number) => ({
      frequency: instance.ParaValue[3]._text,
      protocol: instance.ParaValue[4]._text,
      channel: Number(instance.ParaValue[5]._text),
      beaconInterval: Number(instance.ParaValue[10]._text),
      txPower: Number(instance.ParaValue[11]._text.replace('%', '')),
      band: instance.ParaValue[15]._text,
      enabled: Number(instance.ParaValue[17]._text) === 1,
    }));
    return wlans;
  }

  public async getHosts() {
    const authCookie = await this.login();
    const sessToken = hex2a(
      (
        await axios.get(
          `http://${this.host}:${this.port}/?_type=menuView&_tag=mmTopology&Menu3Location=0&_=${this.time}`,
          {
            headers: {
              Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
            },
          },
        )
      ).data
        .split('_sessionTmpToken = "')[1]
        .split('"')[0]
        .replaceAll('\\x', ''),
    );
    const res = (
      await axios.get(`http://${this.host}:${this.port}/?_type=menuData&_tag=topo_lua.lua&_=${this.time}`, {
        headers: {
          Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
        },
      })
    ).data;
    delete res.ad.MGET_INST_NUM;
    const hosts = Object.values(res.ad).map((host: any) => ({
      time: new Date(host.AssocTime * 1000).toISOString().slice(11, 19),
      hostname: host.HostName,
      ip: host.IpAddr,
      mac: host.MacAddr,
      vendor: toVendor(host.MacAddr),
      signal: Number(host.Rssi),
      rxMbps: Number(host.RxRateMbps),
      txMbps: Number(host.TxRateMbps),
      protocol: host.WirelessMode,
    }));
    return hosts;
  }

  /**
   * Change SSID and Passkey of an Wi-Fi.
   *
   * @param num - The SSID number from 1 to 7
   * @param ssid - The name you want for you SSID
   * @param ssid - The password you want for you SSID
   * @returns True if successful and false if error
   */
  public async changeSSID(num: number, ssid: string, password: string) {
    const authCookie = await this.login();
    const sessToken = hex2a(
      (
        await axios.get(
          `http://${this.host}:${this.port}/?_type=menuView&_tag=wlanBasic&Menu3Location=0&_=${this.time}`,
          {
            headers: {
              Cookie: `SID=${authCookie}; _TESTCOOKIESUPPORT=1`,
            },
          },
        )
      ).data
        .split('_sessionTmpToken = "')[1]
        .split('"')[0]
        .replaceAll('\\x', ''),
    );
    const cryptoKey = randomNum(16);
    const cryptoIv = randomNum(16);
    const data = {
      IF_ACTION: 'Apply',
      Enable: '1',
      _InstID: `DEV.WIFI.AP${num}`,
      _WEPCONIG: 'N',
      _PSKCONIG: 'Y',
      BeaconType: '11i',
      WEPAuthMode: 'None',
      WPAAuthMode: 'PSKAuthentication',
      '11iAuthMode': 'PSKAuthentication',
      WPAEncryptType: 'TKIPandAESEncryption',
      '11iEncryptType': 'AESEncryption',
      _InstID_WEP0: 'DEV.WIFI.AP5.WEP1',
      _InstID_WEP1: 'DEV.WIFI.AP5.WEP2',
      _InstID_WEP2: 'DEV.WIFI.AP5.WEP3',
      _InstID_WEP3: 'DEV.WIFI.AP5.WEP4',
      _InstID_PSK: 'DEV.WIFI.AP5.PSK1',
      MasterAuthServerIp: '...',
      _InstID_GUEST: '',
      _GUEST: 'N',
      GuestWifi: '',
      ESSID: ssid,
      ESSIDHideEnable: '0',
      EncryptionType: 'WPA2-PSK-AES',
      KeyPassphrase: encodePassword(password, cryptoKey, cryptoIv),
      WEPKeyIndex: '1',
      ShowWEPKey: '0',
      WEPKey00: encodePassword('1111', cryptoKey, cryptoIv),
      WEPKey01: encodePassword('2222', cryptoKey, cryptoIv),
      WEPKey02: encodePassword('3333', cryptoKey, cryptoIv),
      WEPKey03: encodePassword('4444', cryptoKey, cryptoIv),
      VapIsolationEnable: '0',
      MaxUserNum: '32',
      Btn_cancel_WLANSSIDConf: '',
      Btn_apply_WLANSSIDConf: '',
      encode: encodeKey(cryptoKey, cryptoIv),
      _sessionTOKEN: sessToken,
    };
    const encodedData = new URLSearchParams(data);
    const options = {
      headers: {
        Accept: '*/*',
        'Accept-Language': 'pt-BR,pt;q=0.9,en-US;q=0.8,en;q=0.7',
        'Cache-Control': 'no-cache',
        Check: asyEncode(CryptoJS.SHA256(toQS(data)).toString()),
        Connection: 'keep-alive',
        'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
        Cookie: `_TESTCOOKIESUPPORT=1; SID=${authCookie}`,
        Origin: `http://${this.host}:${this.port}`,
        Pragma: 'no-cache',
        Referer: `http://${this.host}:${this.port}`,
        'Sec-GPC': '1',
        'User-Agent':
          'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.5060.114 Safari/537.36',
        'X-Requested-With': 'XMLHttpRequest',
      },
    };
    const res = await axios.post(
      `http://${this.host}:${this.port}/?_type=menuData&_tag=wlan_wlansssidconf_lua.lua`,
      encodedData,
      options,
    );
    return String(res.data).includes('<IF_ERRORSTR>SUCC</IF_ERRORSTR>');
  }
}
