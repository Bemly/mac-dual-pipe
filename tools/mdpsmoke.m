// mdpsmoke.m — mac-dual-pipe 独立回环自测（无需手机/控制通道，纯本机验证传输层）：
//
//   原理：进程内起两个桩服务（实现 E/V/M/Q 分帧；M 的变换=逐字节反转），
//   用假 control/ensureForward 喂给 MDPDual，逐项断言。
// 编译（仓库根目录）：
//   clang -arch arm64 -fobjc-arc -framework Foundation tools/mdpsmoke.m \
//     build/Release/libmac-dual-pipe.a -I src -o /tmp/mdpsmoke && /tmp/mdpsmoke
#import <Foundation/Foundation.h>
#import "mac-dual-pipe.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>

static void PutU32(NSMutableData *d, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    [d appendBytes:b length:4];
}
static uint32_t GetU32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static BOOL Fill(int fd, uint8_t *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r <= 0) return NO;
        off += (size_t)r;
    }
    return YES;
}
static BOOL SendAll(int fd, const uint8_t *p, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(fd, p + off, n - off, 0);
        if (r <= 0) return NO;
        off += (size_t)r;
    }
    return YES;
}

static int gStubFd[2] = { -1, -1 };
static int gStubPort[2] = { 0, 0 };

// 已建连接追踪(故障注入用:关监听不断已建连,必须显式关连接才能模拟链路故障)
static NSMutableArray<NSNumber *> *gConns[2];
static NSLock *gConnLock;

typedef struct { int idx; int fd; } ConnArg;

static void TrackAdd(int idx, int fd) {
    [gConnLock lock];
    [gConns[idx] addObject:@(fd)];
    [gConnLock unlock];
}
static void TrackDel(int idx, int fd) {
    [gConnLock lock];
    [gConns[idx] removeObject:@(fd)];
    [gConnLock unlock];
}
// 杀整条桩:停监听 + 断本桩全部已建连(两遍,缝 accept/注册竞态)
static void KillStub(int idx) {
    if (gStubFd[idx] >= 0) {
        shutdown(gStubFd[idx], SHUT_RDWR);
        close(gStubFd[idx]);
        gStubFd[idx] = -1;
    }
    for (int pass = 0; pass < 2; pass++) {
        [gConnLock lock];
        NSArray *snap = [gConns[idx] copy];
        [gConnLock unlock];
        for (NSNumber *n in snap) close(n.intValue);
        [NSThread sleepForTimeInterval:0.2];
    }
}

// 桩连接：E 回显 / V 回代号 T9 / M 反转每条 / Q 断开
static void ServeOne(int idx, int fd) {
    TrackAdd(idx, fd);
    for (;;) {
        uint8_t h[5];
        if (!Fill(fd, h, 5)) break;
        if (GetU32(h) != 0x41443031) break;
        uint8_t cmd = h[4];
        if (cmd == 0x51) break;
        if (cmd == 0x45) {
            uint8_t lb[4];
            if (!Fill(fd, lb, 4)) break;
            uint32_t n = GetU32(lb);
            NSMutableData *b = [NSMutableData dataWithLength:n];
            if (n && !Fill(fd, b.mutableBytes, n)) break;
            NSMutableData *resp = [NSMutableData data];
            PutU32(resp, 0x41443032);
            uint8_t z = 0;
            [resp appendBytes:&z length:1];
            PutU32(resp, n);
            if (n) [resp appendData:b];
            if (!SendAll(fd, resp.bytes, resp.length)) break;
        } else if (cmd == 0x56) {
            NSData *gen = [@"T9" dataUsingEncoding:NSASCIIStringEncoding];
            NSMutableData *resp = [NSMutableData data];
            PutU32(resp, 0x41443032);
            uint8_t z = 0;
            [resp appendBytes:&z length:1];
            PutU32(resp, (uint32_t)gen.length);
            [resp appendData:gen];
            if (!SendAll(fd, resp.bytes, resp.length)) break;
        } else if (cmd == 0x4D) {
            uint8_t fixed[24];
            if (!Fill(fd, fixed, 24)) break;          // slot u32 + iv16 + nl u32
            uint32_t nl = GetU32(fixed + 20);
            NSMutableData *lens = [NSMutableData dataWithLength:nl * 4];
            if (!Fill(fd, lens.mutableBytes, nl * 4)) break;
            uint8_t tb[4];
            if (!Fill(fd, tb, 4)) break;
            uint32_t total = GetU32(tb);
            NSMutableData *ct = [NSMutableData dataWithLength:total];
            if (!Fill(fd, ct.mutableBytes, total)) break;
            NSMutableData *resp = [NSMutableData data];
            PutU32(resp, 0x41443032);
            uint8_t z = 0;
            [resp appendBytes:&z length:1];
            PutU32(resp, nl);
            const uint8_t *lensB = lens.bytes, *ctB = ct.bytes;
            NSUInteger off = 0;
            for (uint32_t i = 0; i < nl; i++) {
                uint32_t n = GetU32(lensB + i * 4);
                PutU32(resp, n);
                for (uint32_t k = 0; k < n; k++) {
                    uint8_t one = ctB[off + n - 1 - k];   // 反转变换
                    [resp appendBytes:&one length:1];
                }
                off += n;
            }
            if (!SendAll(fd, resp.bytes, resp.length)) break;
        } else break;
    }
    // 注意:TrackDel 要 idx,调用方 ServeThread 传
    close(fd);
}

static void *ServeThread(void *arg) {
    ConnArg *a = arg;
    int idx = a->idx, fd = a->fd;
    free(a);
    ServeOne(idx, fd);
    TrackDel(idx, fd);
    return NULL;
}

static void *AcceptLoop(void *arg) {
    int idx = (int)(intptr_t)arg;
    for (;;) {
        int fd = accept(gStubFd[idx], NULL, NULL);
        if (fd < 0) return NULL;   // 监听关了就退出
        ConnArg *a = malloc(sizeof(ConnArg));
        a->idx = idx; a->fd = fd;
        pthread_t t;
        pthread_create(&t, NULL, ServeThread, a);
        pthread_detach(t);
    }
}

static int StubListen(void) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) return -1;
    if (listen(fd, 4) < 0) return -1;
    return fd;
}

static NSData *Reversed(NSData *d) {
    NSMutableData *o = [NSMutableData dataWithLength:d.length];
    const uint8_t *s = d.bytes;
    uint8_t *t = o.mutableBytes;
    for (NSUInteger i = 0; i < d.length; i++) t[i] = s[d.length - 1 - i];
    return o;
}

static int gFails = 0;
static void Check(BOOL ok, const char *name) {
    printf("[%s] %s\n", ok ? "PASS" : "FAIL", name);
    if (!ok) gFails++;
}

int main(int argc, char **argv) {
    @autoreleasepool {
        setbuf(stdout, NULL);   // 自测输出不缓冲,崩了也能看到断点
        gConns[0] = [NSMutableArray array];
        gConns[1] = [NSMutableArray array];
        gConnLock = [NSLock new];
        for (int i = 0; i < 2; i++) {
            gStubFd[i] = StubListen();
            if (gStubFd[i] < 0) { printf("stub listen 失败\n"); return 2; }
            struct sockaddr_in a;
            socklen_t n = sizeof(a);
            getsockname(gStubFd[i], (struct sockaddr *)&a, &n);
            gStubPort[i] = ntohs(a.sin_port);
            pthread_t t;
            pthread_create(&t, NULL, AcceptLoop, (void *)(intptr_t)i);
            pthread_detach(t);
        }
        printf("桩端口: %d/%d\n", gStubPort[0], gStubPort[1]);

        MDPConfig *cfg = [MDPConfig new];
        cfg.basePort = 17001;
        cfg.lanIp = @"127.0.0.1";
        cfg.expectedGen = @"T9";
        cfg.control = ^NSDictionary *(NSString *op, NSDictionary *args, NSTimeInterval to, NSString **err) {
            (void)args; (void)to;
            if ([op isEqualToString:@"start"])
                return @{ @"ok": @YES, @"ports": @[ @(gStubPort[0]), @(gStubPort[1]) ], @"notes": @[] };
            if ([op isEqualToString:@"slot"]) return @{ @"ok": @YES, @"slot": @7 };
            if ([op isEqualToString:@"stop"]) return @{ @"ok": @YES, @"closed": @2 };
            if (err) *err = @"未知 op";
            return nil;
        };
        cfg.ensureForward = ^BOOL (int port, NSString **err) { (void)port; (void)err; return YES; };
        cfg.log = ^(NSString *l) { printf("  %s\n", l.UTF8String); };

        NSString *e = nil;
        MDPDual *dual = [MDPDual buildWithConfig:cfg error:&e];
        Check(dual != nil && dual.linkTotal == 2, "建链双链");
        if (!dual) { printf("建链失败: %s\n", e.UTF8String); return 1; }

        NSMutableData *blob = [NSMutableData dataWithLength:1048576];
        arc4random_buf(blob.mutableBytes, blob.length);
        Check([dual echoAll:blob logf:nil], "1MB 回环");

        NSMutableData *iv = [NSMutableData dataWithLength:16];
        arc4random_buf(iv.mutableBytes, iv.length);
        NSMutableArray<NSData *> *items = [NSMutableArray array];
        for (int i = 0; i < 200; i++) {
            NSMutableData *one = [NSMutableData dataWithLength:32768];
            arc4random_buf(one.mutableBytes, one.length);
            [items addObject:one];
        }
        uint32_t slot = [dual slotForKey:@"k1" spec:@{} error:&e];
        Check(slot == 7, "槽位登记");
        NSArray<NSData *> *got = [dual processMany:slot iv:iv items:items fallback:nil logf:nil error:&e];
        BOOL same = got && got.count == items.count;
        if (same) {
            for (NSUInteger i = 0; i < items.count; i++) {
                if (![got[i] isEqualToData:Reversed(items[i])]) { same = NO; break; }
            }
        }
        Check(same, "200 包/6.4MB 双链变换一致");

        // 杀一条桩 → 转交应仍一致
        KillStub(1);
        got = [dual processMany:slot iv:iv items:items fallback:nil logf:nil error:&e];
        same = got && got.count == items.count;
        if (same) {
            for (NSUInteger i = 0; i < items.count; i++) {
                if (![got[i] isEqualToData:Reversed(items[i])]) { same = NO; break; }
            }
        }
        Check(same, "单链故障转交一致");

        // 全杀 → fallback 兜底
        KillStub(0);
        got = [dual processMany:slot iv:iv items:items
                       fallback:^NSArray<NSData *> *(NSArray<NSData *> *b, NSString **ferr) {
                           (void)ferr;
                           return b;
                       } logf:nil error:&e];
        same = got && got.count == items.count;
        if (same) {
            for (NSUInteger i = 0; i < items.count; i++) {
                if (![got[i] isEqualToData:items[i]]) { same = NO; break; }
            }
        }
        Check(same, "双链全挂回退兜底");

        [dual close];
        [dual close];   // 幂等复调
        printf(gFails ? "SMOKE FAIL(%d)\n" : "SMOKE OK\n", gFails);
        return gFails ? 1 : 0;
    }
}
