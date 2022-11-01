import axios from 'axios';
import Router from '../Common/Router';
import CryptoJS from 'crypto-js';
// import fetch from 'node-fetch';

export default class ZTEv1 extends Router {
  constructor(host: string, port: number, username: string, password: string) {
    super(host, port, username, password);
  }

  private async login() {
    const initData: string = (await axios.get(`http://${this.host}:${this.port}`)).data;
    const sessToken = initData.split('Frm_Loginchecktoken", "')[1].split('"')[0];
    const loginToken = initData.split('Frm_Logintoken", "')[1].split('"')[0];
    const pwdRandom = String(Math.round(Math.random() * 89999999) + 10000000);
    const encodedPassword = CryptoJS.SHA256(this.password + pwdRandom).toString();
    // const res = fetch(`http://${this.host}:${this.port}`, {
    //   method: 'POST',
    //   body: new URLSearchParams({
    //     action: 'login',
    //     Username: this.username,
    //     Password: encodedPassword,
    //     Frm_Logintoken: loginToken,
    //     UserRandomNum: pwdRandom,
    //     Frm_Loginchecktoken: sessToken,
    //   }),
    //   redirect: 'error',
    // }).catch((err) => console.log(err));
  }

  public async getWlans() {
    const cookie = await this.login();
  }
}
