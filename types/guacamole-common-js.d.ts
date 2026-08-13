declare module "guacamole-common-js" {
  interface StaticHTTPTunnelHandle {
    readonly size?: number | null;
  }
  interface SessionRecordingHandle {
    onprogress: ((duration: number, bytes: number) => void) | null;
    onseek: ((position: number) => void) | null;
    onplay: (() => void) | null;
    onpause: (() => void) | null;
    onerror: (() => void) | null;
    connect(): void;
    abort(): void;
    play(): void;
    pause(): void;
    seek(position: number, callback?: () => void): void;
    getDisplay(): {
      getElement(): HTMLElement;
      getWidth(): number;
      getHeight(): number;
      scale(value: number): void;
    };
  }
  const Guacamole: {
    StaticHTTPTunnel: new (
      url: string,
      crossDomain?: boolean,
      headers?: Record<string, string>,
    ) => StaticHTTPTunnelHandle;
    SessionRecording: new (
      source: StaticHTTPTunnelHandle,
    ) => SessionRecordingHandle;
  };
  export default Guacamole;
}
