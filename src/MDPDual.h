#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

// 建链配置:调用方注入环境相关的两块粘合,库内只剩 socket 与调度。
@interface MDPConfig : NSObject

@property (nonatomic, assign) int basePort;   // 起始端口对,<=0 则取 17001
@property (nonatomic, copy, nullable) NSString *lanIp;   // 无线直连地址,nil=只用有线
@property (nonatomic, copy, nullable) NSString *expectedGen; // 对端代号,空则跳过校验

// 控制通道:op @"start" args {@"basePort"} → {@"ok", @"ports":@[p1,p2], @"notes":@[]}
//          op @"slot"  args 调用方自定(spec) → {@"ok", @"slot":@n}
//          op @"stop"   args @{} → {@"ok", @"closed":@n}
@property (nonatomic, copy) NSDictionary * _Nullable (^control)(NSString *op,
                                                                NSDictionary *args,
                                                                NSTimeInterval timeout,
                                                                NSString * _Nullable * _Nullable err);

// 本地转发:保证 127.0.0.1:port 可达对端(失败返回 NO)
@property (nonatomic, copy) BOOL (^ensureForward)(int port, NSString * _Nullable * _Nullable err);

@property (nonatomic, copy, nullable) void (^log)(NSString *line);

@end

@interface MDPDual : NSObject

// 建链:control start → ensureForward → 有线/无线逐条握手(echo+代号) → 定初始权重。
// 零可用链路返回 nil(调用方走备用通道)。
+ (nullable instancetype)buildWithConfig:(MDPConfig *)cfg
                                  error:(NSString * _Nullable * _Nullable)err;

// 槽位登记(spec 透传给 control @"slot";同实例内按 cacheKey 缓存,跨实例需重登)
- (uint32_t)slotForKey:(NSString *)cacheKey
                  spec:(NSDictionary *)spec
                 error:(NSString * _Nullable * _Nullable)err;

// 双链分包并发变换(保序回填);失败转交健康链,全挂调 fallback(与单包同语义)。
// fallback 入参为一批输入(已滤空),返回同序输出,nil 即整体失败。
- (nullable NSArray<NSData *> *)processMany:(uint32_t)slot
                                         iv:(NSData *)iv
                                      items:(NSArray<NSData *> *)cts
                                   fallback:(nullable NSArray<NSData *> *(^)(NSArray<NSData *> *batch, NSString * _Nullable * _Nullable ferr))fallback
                                       logf:(void (^ _Nullable)(NSString *))logf
                                      error:(NSString * _Nullable * _Nullable)err;

// 逐链回环(自检用):每条链全量比对,逐条记行;全过返回 YES
- (BOOL)echoAll:(NSData *)data logf:(void (^ _Nullable)(NSString *))logf;

// 双链并发取文件:按当前权重把 [0,totalSize) 切连续段,各链流式回传、按偏移写入
// localPath(对端零编码原样字节);某段失败转交健康链重试一次。全部成功返回 YES。
- (BOOL)fetchFile:(NSString *)phonePath
           toPath:(NSString *)localPath
        totalSize:(uint64_t)totalSize
             logf:(void (^ _Nullable)(NSString *))logf
            error:(NSString * _Nullable * _Nullable)err;

// 关各链 + control stop(幂等;必须在控制通道失效前调)
- (void)close;

@property (nonatomic, readonly) NSUInteger linkTotal;

@end

NS_ASSUME_NONNULL_END
