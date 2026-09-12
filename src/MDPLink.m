#import "MDPLink.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

// 线上常量(与对端实现逐字节对齐;改动需两端同步,见 README)
static const uint32_t kReqMagic  = 0x41443031; // 'AD01'
static const uint32_t kRespMagic = 0x41443032; // 'AD02'
static const uint8_t kCmdM = 0x4D;             // 批量变换
static const uint8_t kCmdE = 0x45;             // 回显
static const uint8_t kCmdQ = 0x51;             // 断开
static const uint8_t kCmdV = 0x56;             // 代号问询

static const NSTimeInterval kConnTimeout = 5;
static const NSTimeInterval kIoTimeout = 120;

static BOOL TLDebugOn(void) {
    static BOOL v;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ v = getenv("DUALPIPE_DEBUG") != NULL; });
    return v;
}
#define TLDBG(fmt, ...) do { if (TLDebugOn()) NSLog(@"[TL] " fmt, ##__VA_ARGS__); } while (0)

static void PutU32(NSMutableData *d, uint32_t v) {
    uint8_t b[4] = { (uint8_t)(v >> 24), (uint8_t)(v >> 16), (uint8_t)(v >> 8), (uint8_t)v };
    [d appendBytes:b length:4];
}

static uint32_t GetU32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

// ---- socket 原语 ----

static int TlConnectOnce(const char *ip, int port, NSString **err);

static int TlConnect(const char *ip, int port, NSString **err) {
    // 瞬断 WiFi 下首次 connect 常报 No route to host,重试 3 次(每次间隔 1s);
    // 真挂(地址非法除外)最多多花约 2s + 各次自带超时。
    NSString *lastErr = nil;
    for (int attempt = 0; attempt < 3; attempt++) {
        if (attempt > 0) [NSThread sleepForTimeInterval:1.0];
        int fd = TlConnectOnce(ip, port, &lastErr);
        if (fd >= 0) return fd;
        if (lastErr && [lastErr rangeOfString:@"地址非法"].location != NSNotFound) break;
    }
    if (err) *err = lastErr;
    return -1;
}

static int TlConnectOnce(const char *ip, int port, NSString **err) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) { if (err) *err = @"建 socket 失败"; return -1; }
    int one = 1;
    // 发包到已断连接默认发 SIGPIPE 直接打死进程;改走 EPIPE 错误返回(故障转交就靠它)
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
    int fl = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    struct sockaddr_in a;
    memset(&a, 0, sizeof(a));
    a.sin_family = AF_INET;
    a.sin_port = htons((uint16_t)port);
    if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
        close(fd);
        if (err) *err = @"地址非法";
        return -1;
    }
    int r = connect(fd, (struct sockaddr *)&a, sizeof(a));
    if (r < 0 && errno != EINPROGRESS) {
        NSString *e = [NSString stringWithFormat:@"connect: %s", strerror(errno)];
        close(fd);
        if (err) *err = e;
        return -1;
    }
    if (r < 0) {
        fd_set w;
        FD_ZERO(&w);
        FD_SET(fd, &w);
        struct timeval tv = { (int)kConnTimeout, 0 };
        r = select(fd + 1, NULL, &w, NULL, &tv);
        if (r <= 0) {
            close(fd);
            if (err) *err = @"connect 超时";
            return -1;
        }
        int soErr = 0;
        socklen_t n = sizeof(soErr);
        getsockopt(fd, SOL_SOCKET, SO_ERROR, &soErr, &n);
        if (soErr) {
            NSString *e = [NSString stringWithFormat:@"connect: %s", strerror(soErr)];
            close(fd);
            if (err) *err = e;
            return -1;
        }
    }
    fcntl(fd, F_SETFL, fl);
    struct timeval tv2 = { (int)kIoTimeout, 0 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv2, sizeof(tv2));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv2, sizeof(tv2));
    return fd;
}

static BOOL TlSendAll(int fd, const uint8_t *p, size_t n, NSString **err) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(fd, p + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (err) *err = [NSString stringWithFormat:@"send: %s", strerror(errno)];
            return NO;
        }
        off += (size_t)r;
    }
    return YES;
}

static BOOL TlRecvFill(int fd, uint8_t *p, size_t n, NSString **err) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = recv(fd, p + off, n - off, 0);
        if (r < 0) {
            if (errno == EINTR) continue;
            if (err) *err = [NSString stringWithFormat:@"recv: %s", strerror(errno)];
            return NO;
        }
        if (r == 0) {
            if (err) *err = @"对端关闭";
            return NO;
        }
        off += (size_t)r;
    }
    return YES;
}

// 应答头 9B:magic u32 + status u8 + len/nOut u32
static BOOL TlReadHead(int fd, uint32_t *magic, uint8_t *status, uint32_t *num, NSString **err) {
    uint8_t h[9];
    if (!TlRecvFill(fd, h, 9, err)) return NO;
    if (magic) *magic = GetU32(h);
    if (status) *status = h[4];
    if (num) *num = GetU32(h + 5);
    return YES;
}

#pragma mark - 单链

@interface MDPLink ()
@property (nonatomic, assign) int fd;
@property (nonatomic, strong) NSLock *mx;
@property (nonatomic, assign) BOOL shut;
@end

@implementation MDPLink

- (nullable instancetype)initWithName:(NSString *)name
                                addr:(NSString *)addr
                                port:(int)port
                               error:(NSString **)err {
    if ((self = [super init])) {
        NSString *e = nil;
        int fd = TlConnect(addr.UTF8String, port, &e);
        if (fd < 0) { if (err) *err = e; return nil; }
        _name = [name copy];
        _fd = fd;
        _mx = [NSLock new];
        _weight = 1.0;
        TLDBG(@"链路 %@ %@:%d 已连", name, addr, port);
    }
    return self;
}

- (BOOL)echo:(NSData *)data error:(NSString **)err {
    [self.mx lock];
    BOOL ok = NO;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return NO; }
        NSMutableData *body = [NSMutableData data];
        PutU32(body, kReqMagic);
        [body appendBytes:&kCmdE length:1];
        PutU32(body, (uint32_t)data.length);
        if (data.length) [body appendData:data];
        NSString *e = nil;
        if (!TlSendAll(self.fd, body.bytes, body.length, &e)) { if (err) *err = e; return NO; }
        uint32_t magic = 0, ln = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &ln, &e)) { if (err) *err = e; return NO; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return NO; }
        if (st != 0) { if (err) *err = @"回显被拒"; return NO; }
        NSMutableData *back = [NSMutableData dataWithLength:ln];
        if (ln && !TlRecvFill(self.fd, back.mutableBytes, ln, &e)) { if (err) *err = e; return NO; }
        ok = [back isEqualToData:data];
        if (!ok && err) *err = @"回环不一致";
    } @finally {
        [self.mx unlock];
    }
    return ok;
}

- (nullable NSString *)queryGenWithError:(NSString **)err {
    [self.mx lock];
    NSString *gen = nil;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return nil; }
        uint8_t req[5];
        req[0] = (uint8_t)(kReqMagic >> 24); req[1] = (uint8_t)(kReqMagic >> 16);
        req[2] = (uint8_t)(kReqMagic >> 8); req[3] = (uint8_t)kReqMagic; req[4] = kCmdV;
        NSString *e = nil;
        if (!TlSendAll(self.fd, req, 5, &e)) { if (err) *err = e; return nil; }
        uint32_t magic = 0, ln = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &ln, &e)) { if (err) *err = e; return nil; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return nil; }
        if (st != 0) { if (err) *err = @"代号被拒"; return nil; }
        NSMutableData *back = [NSMutableData dataWithLength:ln];
        if (ln && !TlRecvFill(self.fd, back.mutableBytes, ln, &e)) { if (err) *err = e; return nil; }
        gen = [[NSString alloc] initWithData:back encoding:NSASCIIStringEncoding];
    } @finally {
        [self.mx unlock];
    }
    return gen;
}

- (nullable NSArray<NSData *> *)process:(uint32_t)slot
                                     iv:(NSData *)iv
                                  items:(NSArray<NSData *> *)cts
                                  error:(NSString **)err {
    [self.mx lock];
    NSArray<NSData *> *out = nil;
    @try {
        if (self.shut) { if (err) *err = @"已关闭"; return nil; }
        if (iv.length != 16) { if (err) *err = @"IV 非 16B"; return nil; }
        NSUInteger total = 0;
        for (NSData *c in cts) total += c.length;
        NSMutableData *body = [NSMutableData dataWithCapacity:29 + total + cts.count * 4];
        PutU32(body, kReqMagic);
        [body appendBytes:&kCmdM length:1];
        PutU32(body, slot);
        [body appendData:iv];
        PutU32(body, (uint32_t)cts.count);
        for (NSData *c in cts) PutU32(body, (uint32_t)c.length);
        PutU32(body, (uint32_t)total);
        for (NSData *c in cts) if (c.length) [body appendData:c];
        NSString *e = nil;
        if (!TlSendAll(self.fd, body.bytes, body.length, &e)) { if (err) *err = e; return nil; }
        // M 应答无总长前缀:magic/status/nOut + 条目(按条目数读完即止,不依赖总长)
        uint32_t magic = 0, nOut = 0;
        uint8_t st = 0;
        if (!TlReadHead(self.fd, &magic, &st, &nOut, &e)) { if (err) *err = e; return nil; }
        if (magic != kRespMagic) { if (err) *err = @"协议魔数错位"; return nil; }
        if (st != 0) { if (err) *err = @"批量被拒"; return nil; }
        if (nOut != cts.count) {
            if (err) *err = [NSString stringWithFormat:@"返回包数对不上(%u/%lu)", nOut, (unsigned long)cts.count];
            return nil;
        }
        NSMutableArray<NSData *> *res = [NSMutableArray arrayWithCapacity:cts.count];
        for (NSUInteger i = 0; i < cts.count; i++) {
            uint8_t lb[4];
            if (!TlRecvFill(self.fd, lb, 4, &e)) { if (err) *err = e; return nil; }
            uint32_t m = GetU32(lb);
            if (m == 0) { [res addObject:[NSData data]]; continue; }
            NSMutableData *one = [NSMutableData dataWithLength:m];
            if (!TlRecvFill(self.fd, one.mutableBytes, m, &e)) { if (err) *err = e; return nil; }
            [res addObject:one];
        }
        out = res;
    } @finally {
        [self.mx unlock];
    }
    return out;
}

- (void)close {
    [self.mx lock];
    if (!self.shut && self.fd >= 0) {
        uint8_t q[5];
        q[0] = (uint8_t)(kReqMagic >> 24); q[1] = (uint8_t)(kReqMagic >> 16);
        q[2] = (uint8_t)(kReqMagic >> 8); q[3] = (uint8_t)kReqMagic; q[4] = kCmdQ;
        TlSendAll(self.fd, q, 5, NULL);   // 尽力而为,失败直接关
        close(self.fd);
        self.fd = -1;
    }
    self.shut = YES;
    [self.mx unlock];
}

- (void)dealloc { [self close]; }

@end
