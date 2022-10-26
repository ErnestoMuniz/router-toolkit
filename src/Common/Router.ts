export default class Router {
  protected host: string;
  protected port: number;
  protected username: string;
  protected password: string;

  constructor(host: string, port: number, username: string, password: string) {
    this.host = host;
    this.port = port;
    this.username = username;
    this.password = password;
  }
}
