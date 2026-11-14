# c-ares 查询缓存负应答投毒分析

分析对象：本仓库（c-ares，libcares.so.2.19.4）的查询缓存（qcache）对
NXDOMAIN / NODATA 负应答的处理。结论先行：

- **缓存键设计是稳健的**：伪造应答无法污染"别的名字/别的类型"的缓存项，
  跨请求串用基本被杜绝。
- **NXDOMAIN 的 TTL 计算符合 RFC 2308 且有 max_ttl（默认 3600s）截断**，
  伪造 NXDOMAIN 最长造成 1 小时的单名单类型负缓存。
- **NODATA（NOERROR + 空回答段）是真实偏差**：它完全不看 authority 段的
  SOA，缓存期恒为 max_ttl（默认 3600s），与 SOA MINIMUM 无关。伪造一个
  "SOA MINIMUM=60"的 NODATA 应答，也会被缓存整整 1 小时。这是本分析
  发现的主要收紧点，已用本地程序实证（见第 4 节）。

## 1. 代码路径梳理

### 1.1 缓存键（`ares_qcache_calc_key`，src/lib/ares_qcache.c:41）

键在 `ares_send_nolock()`（src/lib/ares_send.c:154）中由**调用方的请求
记录**生成，格式：

```
OPCODE|FLAGS[|EDNS|VER|FLAGS[|ID:HEX]...]|QDCOUNT[|TYPE|CLASS|LEN:QNAME]...
```

- 标志位只取 RD/CD/AD（AD 依据 RFC 6840 §5.7-5.8 会影响应答内容）。
- EDNS 段含版本与 OPT 标志（含 DO 位）；**UDP payload size 与 COOKIE 被
  有意排除**（前者只影响传输不影响内容，后者是每服务器传输状态）。
- 问题段：qtype/qclass 用**数字**而非助记符（未知类型不会都坍缩成
  "UNKNOWN"），qname **长度前缀**防拼接模仿，QDCOUNT 防单问题模仿双
  问题。键对名字**大小写敏感**（DNS0x20 随机化在算键之后才施加到
  `query->query`，见 ares_send.c:154 vs :217，所以不会因此碎片化）。

### 1.2 写入路径与核对顺序（`process_answer`，src/lib/ares_process.c）

应答到达后按以下顺序处理，**全部核对都发生在缓存写入之前**：

1. `ares_dns_parse` 失败即丢弃（:1091）。
2. 按 qid 找到在途查询，找不到即丢弃（:1103）。
3. `same_questions()` 核对问题段（:1111）：问题数、qtype、qclass 逐项
   相等；qname 默认大小写不敏感，开 `ARES_FLAG_DNS0x20` 且非 TCP 时
   大小写敏感（:1803）。
4. `query->conn != conn` 丢弃（:1130）：应答必须到达在发出该查询的
   连接上；UDP 侧 `ares_conn_read()` 还核对源地址/端口（RFC 5452 §9.1，
   端口匹配是超出 RFC 要求的加固）。
5. DNS cookie 验证（:1137）。
6. EDNS 回退检测（:1154）、TC 置位转 TCP 重试（:1170）。
7. SERVFAIL/NOTIMP/REFUSED 不缓存，直接走重试（:1185）。
8. `ares_qcache_insert()`（:1217）→ `end_query()` 回调。

### 1.3 TTL 计算与截断（src/lib/ares_qcache.c）

`ares_qcache_insert_int()`（:436）：

- 只缓存 NOERROR / NXDOMAIN；TC 置位不缓存。
- **NXDOMAIN**：`ares_qcache_soa_minimum()`（:406）取 authority 段第一个
  SOA 的 `min(SOA TTL, SOA MINIMUM)`，即 RFC 2308 §5。无 SOA 时返回 0，
  `ttl == 0` 直接拒绝缓存（:472）。
- **NOERROR（含 NODATA）**：`ares_qcache_calc_minttl()`（:377）取
  ANSWER..ADDITIONAL 三个段中所有 RR 的最小 TTL，但**跳过 OPT/SOA/SIG**。
- 两条路径都经 `ttl = min(ttl, qcache->max_ttl)` 截断（:467），
  `qcache_max_ttl` 默认 3600（src/lib/ares_options.c:494），可用
  `ARES_OPT_QUERY_CACHE` 配置，置 0 即关闭缓存。

### 1.4 读取路径（`ares_qcache_fetch`，:517）

先跑过期清理，命中后按驻留时长递减 TTL，再 `ares_dns_record_duplicate_ex`
复制一份交给回调（回调可重入、可 flush 缓存，不能给它缓存自有的指针）。

## 2. 问题 1：恶意应答能否形成长时间负缓存或跨请求串用？

### 2.1 触发条件

伪造应答要被接受，攻击者需要满足以下之一：

- **在路径上**（能看能改流量）或**上游递归服务器本身恶意/被控**——此时
  下面所有传输层防护都无效，只能靠前述内容级核对与 TTL 截断限制损害；
- **离路径盲注**：需猜中 16 位 qid + UDP 源端口 + 完整问题段；若应用开启
  `ARES_FLAG_DNS0x20` 还需猜中随机大小写；若与服务器协商了 DNS cookie
  还需伪造 cookie。TCP 查询则基本免疫盲注。

### 2.2 能造成什么（实证见第 4 节）

| 伪造应答 | 结果 | 上限 |
|---|---|---|
| NXDOMAIN，SOA TTL=86400，MINIMUM=86400 | 缓存命中至 +3599s，+3601s 过期 | max_ttl 截断生效，最长 3600s |
| **NODATA（NOERROR 空回答），SOA TTL=60，MINIMUM=60** | **+300s、+3599s 仍命中** | **恒为 max_ttl，SOA 被完全忽略** |
| NXDOMAIN，authority 无 SOA | 拒绝缓存（ARES_EREFUSED） | 不缓存 |

- NXDOMAIN 路径符合 RFC 2308，且有 max_ttl 兜底：**单名、单 qtype、最长
  1 小时**的负缓存。损害有界。
- **NODATA 路径是偏差**：`ares_qcache_calc_minttl` 跳过 SOA，空回答的
  NODATA 应答算出的 minttl 是 0xFFFFFFFF，被截断到 max_ttl。攻击者（或
  配置怪异的服务器）给一个 SOA MINIMUM=60 的 NODATA，也被缓存 3600s。
  对 getaddrinfo 场景尤其值得注意：A/AAAA 是两次独立查询，伪造其中
  一个 qtype 的 NODATA（例如"没有 AAAA"）会让该族地址解析在 1 小时内
  持续返回空，而合法区域可能只声明了 60s 的负缓存期。
- 另有一个已记录的有意行为：EDNS 回退（`rewrite_without_edns`）后拿到
  的无 EDNS 应答，仍按**原始带 EDNS 请求的键**缓存
  （ares_qcache.c 中 insert_int 的注释，测试
  `CacheQueriesTest.EdnsFallbackStillCaches` 锁定此行为）。影响轻微：
  后续带 EDNS 的相同查询会吃到一份无 EDNS 时取的答案。

### 2.3 跨请求串用

键包含了调用方可控的全部语义维度（opcode、RD/CD/AD、EDNS 版本/标志/
选项、QDCOUNT、qtype、qclass、qname），且有长度前缀与计数防模仿
（`EdnsSectionCannotBeImitatedByName`、
`UnknownQueryTypesDoNotShareCacheEntries` 等测试锁定）。因此：

- 污染被严格限制在**同名同类同 EDNS 配置**的请求内，无法跨名字、跨
  qtype、跨 DO 位串用；
- 名字大小写不同产生不同键——后果只是多一次缓存未命中，不是串用；
- 缓存键不含响应端内容，响应里的任何 RR 都不可能"写进别人的键"。

### 2.4 现有防护清单

qid 随机化与按 qid 分桶、UDP 源地址+端口匹配、连接归属核对、
same_questions、可选 DNS0x20、DNS cookie、TC 不缓存、
SERVFAIL/NOTIMP/REFUSED 不缓存、无 SOA 的 NXDOMAIN 不缓存、
max_ttl 统一截断、键的注入式编码、命中时返回副本防重入破坏。

## 3. 收紧方案（保留合法负缓存）

按收益排序：

1. **NODATA 也按 RFC 2308 §5 取 SOA 负缓存期**（核心修复）。
   RFC 2308 对 NXDOMAIN 与 NODATA 的负缓存规则是相同的。改法：
   `ares_qcache_insert_int()` 中，当 rcode 为 NOERROR 且 ANSWER 段为空
   （NODATA）时，同样调用 `ares_qcache_soa_minimum()`；无 SOA 时按现状
   不缓存。合法负缓存行为完全保留（合法的 NODATA 本来就该按 SOA
   MINIMUM 缓存），只是把"恒为 max_ttl"的兜底去掉。注意
   `ares_qcache_calc_minttl` 对含回答的 NOERROR 保持不变。
2. **SOA bailiwick 核对**：负缓存前检查 authority 段 SOA 的 owner name
   是 qname 的祖先（或相等）。伪造应答常带与查询名无关的 SOA；不通过
   则拒绝负缓存（正缓存路径不受影响）。c-ares 是 stub resolver，这个
   检查比完整 bailiwick 规则轻量，只用于负缓存判决。
3. **负缓存独立上限**：在 `qcache_max_ttl` 之外引入更小的负缓存上限
   （例如 300s），或至少文档建议应用把 `qcache_max_ttl` 调低。默认
   3600s 对负应答偏长。
4. **QR/opcode 核对**（纵深防御）：`process_answer` 目前不检查 QR 位，
   QR=0 且 qid/问题段匹配的报文也会进入缓存路径。补一个
   `ARES_FLAG_QR` 与 opcode 检查成本极低。
5. **多个 SOA 取最小**：`ares_qcache_soa_minimum` 现在只看第一个 SOA，
   遍历取 `min` 更保守。

## 4. 本地可验证样本

### 4.1 独立探针（已在本机运行）

`/tmp/qcache_probe/qcache_probe.c` 直接驱动内部 qcache API（本构建未开
`CARES_SYMBOL_HIDING`，内部符号可见）。构建与运行：

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -G Ninja -B build && ninja -C build
gcc -g -O0 -DHAVE_CONFIG_H -Ibuild -Iinclude -Isrc/lib -Isrc/lib/include \
    -o /tmp/qcache_probe/qcache_probe /tmp/qcache_probe/qcache_probe.c \
    -Lbuild/lib -lcares -Wl,-rpath,$PWD/build/lib
/tmp/qcache_probe/qcache_probe
```

实测输出（max_ttl=3600，t0 时刻插入）：

```
NXDOMAIN soa_ttl=86400 minimum=86400: insert=Successful completion hit@+60=1 hit@+300=1 hit@+3599=1 hit@+3601=0
NODATA   soa_ttl=60    minimum=60   : insert=Successful completion hit@+60=1 hit@+300=1 hit@+3599=1 hit@+3601=0
NXDOMAIN no SOA                     : insert=DNS server refused query hit@+60=0 hit@+300=0 hit@+3599=0 hit@+3601=0
key(case differs) equal=0
  k1=QUERY|rd|1|1|1|18:victim.example.com
  k2=QUERY|rd|1|1|1|18:Victim.Example.COM
key(EDNS DO differs) equal=0
  k1=QUERY|rd|1|1|1|18:victim.example.com
  k2=QUERY|rd|EDNS|0|8000|1|1|1|18:victim.example.com
```

读法：

- 第 1 行：NXDOMAIN 的 SOA 86400 被 max_ttl 截断为 3600——截断生效。
- **第 2 行：SOA MINIMUM=60 的 NODATA 在 +300s、+3599s 仍命中——
  RFC 2308 要求 60s 过期，实际缓存了 3600s，偏差实证。**
- 第 3 行：无 SOA 的 NXDOMAIN 不缓存。
- 第 4/5 组：名字大小写、EDNS DO 位都分隔缓存键，无串用。

探针要点：伪造响应用 `ares_dns_record_create` + authority 段 SOA 构造；
`ares_qcache_insert` 需要 `query->qcache_key`（由
`ares_qcache_calc_key(请求)` 生成）与 `channel->qcache`；用递增的
`now.sec` 探测不同存活期。注意探测必须**顺序**求值——晚时间点的探测
会触发过期清理，printf 参数求值顺序未定义曾导致误导性结果。

### 4.2 可移植到测试套件的用例

仓库已有 `CacheQueriesTest` 夹具（test/ares-test-mock.cc:629，
`qcache_max_ttl=3600`，mock DNS 服务器）。针对修复（方案 1）的回归
测试思路：

```cpp
TEST_P(CacheQueriesTest, NoDataHonorsSoaMinimum) {
  // mock 服务器对 www.example.com A 返回 NOERROR、空回答段、
  // authority SOA TTL=60 MINIMUM=60；qcache_max_ttl=3600。
  // 第一次查询：ARES_ENODATA（走网络）。
  // 61 秒内第二次查询：命中缓存（合法负缓存保留）。
  // 61 秒后第三次查询：应重新走网络——修复前会错误地继续命中至 3600s。
}
```

以及对应的正向用例 `NxdomainCacheCappedByMaxTtl`（SOA MINIMUM=86400 时
3600s 后必须重新查询）和 `NxdomainWithoutSoaNotCached`。mock 侧可参考
test/ares-test-mock.cc:1389 起现有的 NXDOMAIN 应答构造方式。

## 5. 结论

缓存键与写入前核对的工程设计是到位的，跨请求串用风险低；NXDOMAIN 的
负缓存期有 RFC 2308 语义和 max_ttl 双重约束，伪造 NXDOMAIN 的损害有界
（单名单类型最长 1 小时）。真正需要修的是 **NODATA 负缓存完全忽略 SOA、
恒按 max_ttl 缓存**这一点——它既是 RFC 2308 合规性问题，也是伪造
NODATA 应答的放大器，修复方案（第 3 节第 1 条）不改变任何合法负缓存
行为。
