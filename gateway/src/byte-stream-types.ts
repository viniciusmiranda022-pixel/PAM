/** Interface minima que o handshake consome — facilita fakes em teste. */
export interface ByteStreamReader {
  read(n: number): Promise<Buffer>;
  detach(): Buffer;
}
