# mac-dual-pipe

[中文文档](README.zh.md)

A dual-link binary transport static library for macOS (pure Objective-C, zero third-party dependencies).

Two links (wired forwarding + wireless direct) run concurrently with dynamic
load splitting driven by live throughput measurement; a failed link hands off
to the healthy one automatically, total failure falls back to a spare channel,
and a lagging link is fused for 30s. Bulk traffic uses pure binary frames —
no text-encoding overhead.

## Wire protocol (big-endian throughout, byte-aligned on both ends)

- Request `MAGIC'AD01' + cmd`
  - `M` batch: slot u32 + iv16B + item count u32 + lens[n] u32 + total length u32 + input
  - `E` echo: len u32 + bytes
  - `Q` disconnect; `V` generation query
- Response `MAGIC'AD02' + status u8 (0=ok)`
  - `M`: count u32 + `[len u32 + bytes]*` (no total-length prefix, streamed; read until count reached)
  - `E`: len + bytes; `V`: generation string verbatim

## Control contract (implemented by the caller via `MDPConfig.control`, transport-agnostic)

- `start {basePort}` → `{ok, ports:[p1,p2], notes:[]}` (ports may shift on conflict)
- `slot spec` → `{ok, slot:n}` (spec contents are caller-defined; only a small integer handle goes on the wire)
- `stop {}` → `{ok, closed:n}`

The caller must also implement `ensureForward(port)` (guaranteeing
`127.0.0.1:port` reaches the peer) and provide the wireless address
(`lanIp`; wired-only when absent).

## Lifecycle discipline

Peer-side service threads must be shut down **deterministically**: call `close`
(close all links + control stop) before the control channel goes away. If an
abnormal exit leaves residue behind, port shifting + generation check
(`expectedGen` mismatch means a stale instance — skip it) cover you.

## Build & self-test

```bash
# Static library (dual-arch)
xcodebuild -project mac-dual-pipe.xcodeproj -target mac-dual-pipe -configuration Release SYMROOT=build build
# → build/Release/libmac-dual-pipe.a, headers in src/

# Loopback self-test (no device needed: in-process stub implements the framing, M transform = byte reversal)
clang -arch arm64 -fobjc-arc -framework Foundation tools/mdpsmoke.m \
  build/Release/libmac-dual-pipe.a -I src -o /tmp/mdpsmoke && /tmp/mdpsmoke
```

Troubleshooting: set `DUALPIPE_DEBUG=1` for in-library tracing (stderr).

## Usage

```objc
MDPConfig *cfg = [MDPConfig new];
cfg.basePort = 17001;
cfg.lanIp = lanIpOrNil;
cfg.expectedGen = @"A7";
cfg.control = ^NSDictionary *(NSString *op, NSDictionary *args, NSTimeInterval t, NSString **e) {
    return MyControl(op, args, t, e);   // start/slot/stop
};
cfg.ensureForward = ^BOOL (int port, NSString **e) {
    return MyEnsureForward(port, e);
};
MDPDual *dual = [MDPDual buildWithConfig:cfg error:&err];
uint32_t slot = [dual slotForKey:cacheKey spec:spec error:&err];
NSArray *out = [dual processMany:slot iv:iv items:in
                        fallback:^NSArray *(NSArray *b, NSString **e) { return MyFallback(b, e); }
                            logf:^(NSString *l) { NSLog(@"%@", l); } error:&err];
[dual close];   // close when done, idempotent
```

Reference performance (localhost loopback, stub doing byte reversal): dual-link
handshake at ~13MB/s; production throughput depends on peer transform speed and
the real network.
