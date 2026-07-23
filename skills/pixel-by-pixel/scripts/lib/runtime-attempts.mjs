export const runtimeAttemptFields = Object.freeze({
  websocket: 'webSocketAttempts',
  beacon: 'beaconAttempts',
  windowOpen: 'windowOpenAttempts',
  popup: 'popupAttempts',
  download: 'downloadAttempts',
  serviceWorker: 'serviceWorkerRegistrationAttempts',
  externalFetch: 'externalFetchAttempts',
  externalXhr: 'externalXhrAttempts',
  webTransport: 'webTransportAttempts',
  webSocketStream: 'webSocketStreamAttempts',
  rtcPeerConnection: 'rtcPeerConnectionAttempts',
  rtcDataChannel: 'rtcDataChannelAttempts'
});

export function createRuntimeAttemptTelemetry() {
  return Object.fromEntries(Object.values(runtimeAttemptFields).map((field) => [field, []]));
}

export function recordRuntimeAttempt(telemetry, kind, details = {}, limit = 100) {
  const field = runtimeAttemptFields[kind];
  if (!field || !Array.isArray(telemetry?.[field]) || telemetry[field].length >= limit) return;
  telemetry[field].push({ ...details });
}

export function runtimeAttemptInitScript({ blockEffects }) {
  const report = globalThis.__replicaReportRuntimeAttempt;
  const record = (kind, details = {}) => {
    try { void report({ kind, ...details }); } catch {}
  };
  const urlText = (value) => {
    try { return String(value ?? ''); } catch { return ''; }
  };

  try {
    const nativeFetch = globalThis.fetch?.bind(globalThis);
    if (nativeFetch) {
      Object.defineProperty(globalThis, 'fetch', {
        configurable: true,
        value(input, init) {
          const rawUrl = input instanceof Request ? input.url : input;
          try {
            const target = new URL(urlText(rawUrl), location.href);
            if (['http:', 'https:'].includes(target.protocol) && target.origin !== location.origin) {
              record('externalFetch', { url: target.href, method: String(init?.method || (input instanceof Request ? input.method : 'GET')).toUpperCase() });
            }
          } catch {}
          return nativeFetch(input, init);
        }
      });
    }
  } catch {}

  try {
    const nativeOpenXhr = XMLHttpRequest.prototype.open;
    Object.defineProperty(XMLHttpRequest.prototype, 'open', {
      configurable: true,
      writable: true,
      value(method, url, ...rest) {
        try {
          const target = new URL(urlText(url), location.href);
          if (['http:', 'https:'].includes(target.protocol) && target.origin !== location.origin) {
            record('externalXhr', { url: target.href, method: String(method || 'GET').toUpperCase() });
          }
        } catch {}
        return nativeOpenXhr.call(this, method, url, ...rest);
      }
    });
  } catch {}

  try {
    const nativeSendBeacon = navigator.sendBeacon?.bind(navigator);
    if (nativeSendBeacon) {
      Object.defineProperty(navigator, 'sendBeacon', {
        configurable: true,
        value(url, data) {
          record('beacon', {
            url: urlText(url),
            payloadPresent: data !== undefined && data !== null
          });
          return blockEffects ? false : nativeSendBeacon(url, data);
        }
      });
    }
  } catch {}

  try {
    const nativeOpen = globalThis.open?.bind(globalThis);
    if (nativeOpen) {
      Object.defineProperty(globalThis, 'open', {
        configurable: true,
        value(url, target, features) {
          record('windowOpen', { url: urlText(url), target: urlText(target) });
          return blockEffects ? null : nativeOpen(url, target, features);
        }
      });
    }
  } catch {}

  try {
    const nativeAnchorClick = HTMLAnchorElement.prototype.click;
    Object.defineProperty(HTMLAnchorElement.prototype, 'click', {
      configurable: true,
      writable: true,
      value() {
        const popup = String(this.target || '').toLowerCase() === '_blank';
        const download = this.hasAttribute('download');
        if (popup) record('popup', { url: urlText(this.href) });
        if (download) record('download', { url: urlText(this.href) });
        if (blockEffects && (popup || download)) return undefined;
        return nativeAnchorClick.call(this);
      }
    });
  } catch {}

  try {
    const NativeWebSocket = globalThis.WebSocket;
    if (NativeWebSocket) {
      globalThis.WebSocket = new Proxy(NativeWebSocket, {
        construct(Target, argumentsList, NewTarget) {
          record('websocket', { url: urlText(argumentsList[0]) });
          if (blockEffects) throw new DOMException('WebSocket blocked by pixel-by-pixel.', 'SecurityError');
          return Reflect.construct(Target, argumentsList, NewTarget);
        }
      });
    }
  } catch {}

  for (const [globalName, kind, label] of [
    ['WebTransport', 'webTransport', 'WebTransport'],
    ['WebSocketStream', 'webSocketStream', 'WebSocketStream']
  ]) {
    try {
      const NativeTransport = globalThis[globalName];
      if (!NativeTransport) continue;
      Object.defineProperty(globalThis, globalName, {
        configurable: true,
        writable: true,
        value: new Proxy(NativeTransport, {
          construct(Target, argumentsList, NewTarget) {
            record(kind, { url: urlText(argumentsList[0]) });
            if (blockEffects) throw new DOMException(`${label} blocked by pixel-by-pixel.`, 'SecurityError');
            return Reflect.construct(Target, argumentsList, NewTarget);
          }
        })
      });
    } catch {}
  }

  try {
    const peerPrototype = globalThis.RTCPeerConnection?.prototype
      || globalThis.webkitRTCPeerConnection?.prototype;
    const nativeCreateDataChannel = peerPrototype?.createDataChannel;
    if (nativeCreateDataChannel) {
      Object.defineProperty(peerPrototype, 'createDataChannel', {
        configurable: true,
        writable: true,
        value(label, options) {
          record('rtcDataChannel', {
            labelPresent: urlText(label).length > 0,
            negotiated: options?.negotiated === true,
            protocolPresent: urlText(options?.protocol).length > 0
          });
          if (blockEffects) throw new DOMException('RTC data channel blocked by pixel-by-pixel.', 'SecurityError');
          return nativeCreateDataChannel.call(this, label, options);
        }
      });
    }
  } catch {}

  for (const globalName of ['RTCPeerConnection', 'webkitRTCPeerConnection']) {
    try {
      const NativePeerConnection = globalThis[globalName];
      if (!NativePeerConnection) continue;
      Object.defineProperty(globalThis, globalName, {
        configurable: true,
        writable: true,
        value: new Proxy(NativePeerConnection, {
          construct(Target, argumentsList, NewTarget) {
            const configuration = argumentsList[0];
            record('rtcPeerConnection', {
              configurationPresent: configuration !== undefined && configuration !== null,
              iceServerCount: Array.isArray(configuration?.iceServers) ? configuration.iceServers.length : 0
            });
            if (blockEffects) throw new DOMException('RTCPeerConnection blocked by pixel-by-pixel.', 'SecurityError');
            return Reflect.construct(Target, argumentsList, NewTarget);
          }
        })
      });
    } catch {}
  }

  try {
    const serviceWorker = navigator.serviceWorker;
    const nativeRegister = serviceWorker?.register?.bind(serviceWorker);
    if (nativeRegister) {
      Object.defineProperty(serviceWorker, 'register', {
        configurable: true,
        value(scriptURL, options) {
          record('serviceWorker', {
            url: urlText(scriptURL),
            scope: urlText(options?.scope)
          });
          if (blockEffects) {
            return Promise.reject(new DOMException('Service-worker registration blocked by pixel-by-pixel.', 'SecurityError'));
          }
          return nativeRegister(scriptURL, options);
        }
      });
    }
  } catch {}
}
