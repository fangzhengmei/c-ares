# TXT RDATA 边界诊断：长度字节、空 RDATA 与新旧解析接口

分析对象：本仓库 `src/lib/record/ares_dns_multistring.c` 的字符字符串
（`<character-string>`）逐段解析，以及它上层的 `ares_dns_parse()`、
`ares_dns_rr_get_abin()/get_bin()` 和 legacy 封装
`ares_parse_txt_reply()`/`ares_parse_txt_reply_ext()`。

结论先行：

1. **记录边界确实传进了逐段解析，但只用于"循环是否继续"，没有用于
   "这一段能不能读完"。** `ares_dns_multistring_parse_buf()` 的
   `remaining_len` 就是本 RR 的 RDLENGTH（`ares_dns_parse.c:297` 直接把
   `rdlength` 传下去），但循环体只检查*长度字节之前*的偏移，随后
   `ares_buf_fetch_bytes_dup(buf, len, ...)` 用的是**整个报文剩余长度**，
   不是 RDATA 剩余长度。因此长度字节声明 N 字节、而 RDATA 只剩 M<N 字节时，
   helper 会静默地读到相邻记录里（实测见 §4 的 D/E/F/G 与 §7 的 helper 测试）。

2. **真正的越界读取发生在内部 helper 层；公共 API 目前靠"事后总闸"
   fail-closed，而不是靠边界语义。** `ares_dns_parse_rr()` 在 helper 返回
   后会算 `processed_len`，一旦 `processed_len > rdlength` 就返回
   `ARES_EBADRESP`（`ares_dns_parse.c:1547-1552`）。所以经
   `ares_dns_parse()` 进入时，越界 payload **不会**交给调用方；但这条
   防线依赖"越界字节数恰好让总消费量超标"，并且对声明 RDLENGTH 本来就
   覆盖邻居头部的报文（§4 G）并不适用。这一点直接决定了修复和回归测试
   应该放在 helper 那一层（§7/§8）。

3. **"新旧接口给出不同结果"主要来自语义差异，而不是越界**：
   (a) 空 RDATA（`RDLENGTH == 0`）在新解析器里是硬错误，legacy 封装也
   一概返回 `ARES_EBADRESP`；(b) legacy 封装在"有答案但扫不到 TXT 记录"
   时返回 `ARES_SUCCESS` + `*out == NULL`（两个入口行为相同），而无答案
   时返回 `ENODATA`（§4 P/Q/R 行）——"没找到"和"成功但为空"混在一起。
   另外 `get_bin()`（拼接接口）对 0 个字符串的 RR 返回 `NULL`，而空字符串
   的 RR 返回非 NULL 且 `len == 0`，这两种"都是空"在调用方看来无法区分。

4. 修复是**一处边界检查**（6 行有效代码 + 注释），只收紧畸形输入的接受面，
   合法 TXT（含 255 字节边界、空字符串、大量短字符串）结果不变。
   回归测试放在 `test/ares-test-internal.cc`（直接测 helper，**打补丁前失败**）
   和 `test/ares-test-parse-txt.cc`（锁定公共入口继续 fail-closed，两层都
   通过）。全量 `-*Live*` 763 个用例通过。

---

## 1. 解析链全景

```
ares_parse_txt_reply[_ext]()            src/lib/legacy/ares_parse_txt_reply.c:126/136
 └─ ares_parse_txt_reply_int()          :30
     ├─ ares_dns_parse()                src/lib/record/ares_dns_parse.c:1717
     │   └─ ares_dns_parse_buf()        :1567
     │       └─ ares_dns_parse_rr()     :1425
     │           ├─ rdlength = u16      :1497      ← 记录边界在此取得
     │           ├─ if (rdlength > ares_buf_len(buf)) EBADRESP   :1521
     │           ├─ remaining_len = ares_buf_len(buf)            :1537
     │           ├─ ares_dns_parse_rr_data(..., rdlength, ...)   :1540
     │           │   └─ ares_dns_parse_rr_txt()                  :294
     │           │       └─ ares_dns_parse_and_set_dns_abin()    :93
     │           │           └─ ares_dns_multistring_parse_buf() ares_dns_multistring.c:239  ← 逐段解析
     │           ├─ processed_len = remaining_len - ares_buf_len(buf)  :1547
     │           ├─ if (processed_len > rdlength) EBADRESP        :1550  ← 事后总闸
     │           └─ if (processed_len < rdlength) 丢弃尾部       :1557
     └─ 遍历 ANSWER 段，rr 类型/类过滤，逐 j 取 ares_dns_rr_get_abin()  :61-104

ares_dns_rr_get_abin(rr, ARES_RR_TXT_DATA, j, &len)   src/lib/record/ares_dns_record.c:1063
 └─ ares_dns_multistring_get()                          ares_dns_multistring.c:176

ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &len)       src/lib/record/ares_dns_record.c:1006
 └─ ares_dns_multistring_combined()                     ares_dns_multistring.c:194  ← 拼接接口
```

## 2. 记录边界如何传入逐段解析

`ares_dns_parse_rr()` 的流程是"先取 RDLENGTH，再信任它解析 RDATA，最后
用实际消费量与 RDLENGTH 比对"：

- `rdlength` 取自线上 16 位字段（`ares_dns_parse.c:1497`）。
- 唯一的**前置**检查是 `rdlength > ares_buf_len(buf)`
  （`ares_dns_parse.c:1521`）：RDLENGTH 不能超过**整个报文**剩余长度。
  注意这不是"不能超过本记录"，只是防溢出。
- `remaining_len = ares_buf_len(buf)`（:1537）记下 RDATA 起点的报文绝对
  剩余长度，随后把 `rdlength` 作为 `max_len` 一路传到
  `ares_dns_multistring_parse_buf(buf, rdlength, ...)`（`ares_dns_parse.c:297`）。
  **从这里开始，边界是"传入"的，而不是"隔离"的**——`buf` 仍是整条报文的
  const 缓冲区，helper 可以自由读后面。

也就是说，RDATA 边界是靠一个**软上限参数 + 事后总闸**实现的，中间没有
子缓冲区。

## 3. 逐段解析如何处理剩余长度

`ares_dns_multistring_parse_buf()`（`ares_dns_multistring.c:239`）的核心循环：

```c
orig_len = ares_buf_len(buf);                       /* 进入时的报文剩余 */

if (remaining_len == 0)                             /* :252 */
  return ARES_EBADRESP;

while (orig_len - ares_buf_len(buf) < remaining_len) {   /* :263 条件只看“起点” */
  status = ares_buf_fetch_bytes(buf, &len, 1);           /* :264 取长度字节 */
  ...
  if (len && validate_printable && ares_buf_len(buf) >= len) {  /* :272 */
    ...
  }
  if (strs != NULL) {
    if (len) {
      status = ares_buf_fetch_bytes_dup(buf, len, ARES_TRUE, &data); /* :284 */
    }
    status = ares_dns_multistring_add_own(*strs, data, len);         /* :289 */
  } else {
    status = ares_buf_consume(buf, len);                             /* :296 */
  }
}
```

**关键缺陷**：`:263` 的循环条件在每次迭代开始时检查"已消费 < `remaining_len`"，
于是它只保证**长度字节本身**落在 RDATA 内。`len` 一旦被读入，`:284`
的 `ares_buf_fetch_bytes_dup()` 只校验"报文剩余 >= `len`"
（`ares_buf.c:752-772`），**不校验 "RDATA 剩余 >= `len`"**。当
`RDATA 剩余 < len <= 报文剩余` 时，payload 直接跨过 RDLENGTH 读到下一条
记录，然后：

- 若被吞掉的字节恰好让总消费量 `> rdlength`，`ares_dns_parse_rr()`
  在 :1550 用 `ARES_EBADRESP` 兜住（**公共 API 因此看不到污染数据**）；
- 若总消费量仍 `<= rdlength`（比如长度字节正好在 RDATA 最后一个字节，
  吞掉的是**下一条记录头的前几个字节**，而这些字节"本应"属于本条 RDATA），
  则报文**解析成功**，相邻记录的字节就变成了 TXT payload（§4 G 行）。

对比同一仓库里另一处同类解析器 `ares_buf_parse_dns_binstr_int()`
（`ares_buf.c:1500-1566`），它做了正确的检查：

```c
status = ares_buf_fetch_bytes(buf, &len, 1);
remaining_len--;
if (len > remaining_len) {            /* :1529 —— 用 RDATA 剩余校验 */
  status = ARES_EBADRESP;
  goto done;
}
```

`ares_dns_multistring_parse_buf()` 是唯一漏掉这一步的 RDATA 列表解析器。
`ares_dns_parse_rr_hinfo()/caa()/uri()` 等单串类型都通过
`ares_dns_rr_remaining_len()`（`ares_dns_parse.c:32`）显式计算 RDATA 剩余，
唯独 TXT 走的 multistring helper 没有。

## 4. 本地复现（合法多字符串 / 边界 / 跨边界 / 空 RDATA / 大量字符串）

方法：构造原始应答字节，question 固定为 `example.com TXT IN`，答案 RR 的
owner name 用压缩指针指向 question（`c0 0c`），RDATA 按需逐字节布置。
对同一份字节分别调用

- `ares_dns_parse()`（新接口）→ `rr_cnt`、`abin_cnt`、`get_bin()` 的
  `combined_len`；
- `ares_parse_txt_reply()`（旧接口）→ 返回码、链表节点数、payload 总字节；
- `ares_parse_txt_reply_ext()` → 返回码、`record_start`。

"past boundary" 一列是由内部 harness 直接观测 helper 的
`consumed - rdlength` 得到的，用于区分"公共 API 兜住"和"根本没越界"。

### 4.1 合法与边界内

| # | 场景 | wire | `ares_dns_parse` | `abin_cnt` | `get_bin` len | legacy nodes / bytes | ext |
|---|---|---|---|---|---|---|---|
| A | 合法多字符串 `"ab","cd"` | 47 | 0 | 2 | 4 | 2 / 4 | 0 |
| B | 单个 255 字节串（1+255=256，恰等于 RDLENGTH） | 297 | 0 | 1 | 255 | 1 / 255 | 0 |
| C | 2 + 253 字节（和恰等于 RDLENGTH 257） | 298 | 0 | 2 | 255 | 2 / 255 | 0 |
| T | 单个 254 字节串 | 296 | 0 | 1 | 254 | 1 / 254 | 0 |
| U | 1 + 255 字节 | 299 | 0 | 2 | 256 | 2 / 256 | 0 |
| J | 单个空字符串 `{00}`（RDLENGTH 1） | 42 | 0 | 1 | **0** | 1 / 0 | 0 |

### 4.2 跨边界（长度字节超出 RDATA 剩余）

| # | 场景 | wire | 内部 helper 是否越过 RDLENGTH | `ares_dns_parse` | legacy | ext |
|---|---|---|---|---|---|---|
| D | `{01 'a' 05}`，RDATA 长 3，报文在此结束 | 44 | 否（报文也没字节了） | 10 | 10 | 10 |
| E | 同 D，但后面还有一条合法 TXT RR | 60 | **是**（helper 读到 RDLENGTH 之外） | 10 | 10 | 10 |
| F | 先合法 TXT，后接 D 的畸形 RR | 60 | 是 | 10 | 10 | 10 |
| G | RR0 `RDLENGTH=15`：`{01 'a' 0c}` + 12 字节长度内容**正好是 RR1 的完整头部**，后面再接一条真正的 RR1 | 72 | 否（都在声明的 15 内） | **0** | **0** | 0 |
| S | `{ff}` 单字节，RDLENGTH 1 | 42 | 否 | 10 | 10 | 10 |

G 行是关键：报文结构上完全自洽（RDLENGTH 确实覆盖了那 15 字节），解析器
按声明读，于是 **RR0 的第二个字符串就是 RR1 的头部字节
`c0 0c 00 10 00 01 00 00 00 64 00 02`**。实测：

```
CASE G rdlen_absorbs_hdr wire=72 | new st=0 rr=2
  | rr0(ty=16,cl=1,abin=2,comb=13)[1][12]      ← 第二个串长 12，内容为邻居头部
  | rr1(ty=16,cl=1,abin=2,comb=2)[1][1]
  | old rc=0 nodes=4 bytes=15
```

E/F 行说明 `ares_dns_parse_rr()` 的事后总闸（`processed_len > rdlength`）
确实生效：越界读取发生了，但公共 API 返回 `ARES_EBADRESP`，不会把污染
字符串交给调用方。**这是"防御性兜底"，不是正确的边界检查**——它依赖
"越界字节数恰好让总消费量超标"，换一种布局（G，或直接调用 helper，
见 §7 的 `consumed=8 > rdlength=3` 但返回 `ARES_SUCCESS`）就不再成立，
而且 helper 本身（`ares_dns_multistring_parse_buf` 是 semi-public 的
内部 API，`src/lib/record/ares_dns_multistring.h:67`）没有任何边界承诺。

### 4.3 空 RDATA

| # | 场景 | wire | `ares_dns_parse` | legacy | ext |
|---|---|---|---|---|---|
| H | 唯一答案 RR 的 RDATA 为空（RDLENGTH 0） | 41 | **10** | **10** | 10 |
| I | 先一条合法 TXT，再来一条空 RDATA 的 TXT | 57 | **10** | **10** | 10 |
| — | 合法 TXT + authority 段空 RDATA TXT | — | **10** | **10** | 10 |

空 RDATA 被拒绝的原因是 `ares_dns_multistring_parse_buf()` 的
`if (remaining_len == 0) return ARES_EBADRESP;`（`ares_dns_multistring.c:252`）。
对 TXT 而言这**可以说得过去**：RFC 1035 §3.3 规定 TXT-DATA 是
"one or more `<character-string>`"，0 条字符串不是合法 TXT。但它带来的
副作用值得记录：

- 一条**别处**的空 RDATA TXT（例如 authority 段里的）会让**整条报文**
  `ares_dns_parse()` 失败，连带同一报文里已经解析好的答案都拿不到；
- RFC 1035 本身并不要求接收方对 RDLENGTH=0 的 TXT 回以错误（"parse
  tolerantly"），但这是**发送方**畸形，拒绝是保守且可辩护的；
- 真正需要留意的是**空字符串** `{00}`（J 行）是合法的、会被保留，
  但 `get_bin()` 返回的 `len == 0` 与"根本没有字符串"（R 行，返回
  `NULL`）无法区分，见 §5。

### 4.4 大量短字符串

| # | 场景 | wire | `abin_cnt` | `get_bin` len | legacy nodes / bytes | 峰值 RSS 增量 |
|---|---|---|---|---|---|---|
| K | 300 个空字符串 | 341 | 300 | 0 | 300 / 0 | — |
| L | 260 个单字节字符串 | 561 | 260 | 260 | 260 / 260 | — |
| M | 30000 个单字节字符串 | 60041 | 30000 | 30000 | 30000 / 30000 | — |
| N | 65490 个空字符串（接近 64 KiB 上限） | 65531 | 65490 | 0 | 65490 / 0 | 新 3128 KiB（≈49×） 旧 9208 KiB（≈144×） |

N 行展示了内存放大：65 KiB 的报文能让**新接口**多占约 3 MiB、**旧接口**
多占约 9 MiB。新接口每个空串一个 `ares_array` 元素 + 一个 1 字节占位
（`ares_dns_multistring_add_own()` 对 `len == 0` 还要 `ares_malloc_zero(1)`，
`ares_dns_multistring.c:149-159`）；旧接口每个字符串再额外一个
`struct ares_data` 头 + 一个 `txt` 分配。这是设计使然（逐串保留），
但在接受 64 KiB 远程应答时要意识到它。**不是本次修复的范围**。

### 4.5 新旧接口结果差异（与边界无关）

| # | 场景 | `ares_dns_parse` | `ares_parse_txt_reply` | `ares_parse_txt_reply_ext` |
|---|---|---|---|---|
| O | TXT class CHAOS(3) | 0, abin=1 | 0, nodes=1 | 0 |
| P | TXT class HS(4) | 0, abin=1 | **0，但 `*out == NULL`** | **0，`*out == NULL`** |
| Q | 无答案 RR | 0, rr=0 | **ENODATA(1)** | **ENODATA(1)** |
| R | 只有 CNAME 答案 | 0, rr=1, abin=0 | **0，但 `*out == NULL`** | **0，`*out == NULL`** |

- P/R 行：legacy 封装只接受 `IN`/`CHAOS`（`ares_parse_txt_reply.c:66-71`），
  扫不到目标记录时**不设置** `status`，`status` 保持函数入口的
  `ARES_SUCCESS`，于是返回成功 + 空链表；两个入口
  （`ares_parse_txt_reply` / `_ext`）此行为一致。调用方很难区分
  "成功但没有 TXT"和"我没检查到"。
- Q 行：`ares_dns_record_rr_cnt(ANSWER) == 0` 时返回 `ARES_ENODATA`
  （`ares_parse_txt_reply.c:47-50`）。注意这与 P/R 语义不一致：
  "没有答案"是错误，"有答案但没有 TXT"是成功。
- J vs R 行：`get_bin()` 对空字符串返回非 `NULL` + `len == 0`，对
  0 个字符串返回 `NULL`。两者都是"空 TXT"，调用方的
  `if (ptr && len)` 与 `if (ptr)` 会给出不同结论。

这些差异是 legacy 兼容层的历史行为（`docs/ares_parse_txt_reply.3` 只
承诺"解析成链表"），**本次不修改**，但写进报告，避免被误当成边界 bug。

## 5. 拼接接口如何处理剩余长度

`ares_dns_rr_get_bin(rr, ARES_RR_TXT_DATA, &len)`
（`ares_dns_record.c:1006-1029`）对 `ARES_DATATYPE_ABINP` 走
`ares_dns_multistring_combined()`（`ares_dns_multistring.c:194-236`）：

```c
for (i = 0; i < ares_array_len(strs->strs); i++) {
  data = ares_array_at_const(strs->strs, i);
  ares_buf_append(buf, data->data, data->len);     /* :222 纯拼接 */
}
strs->cache_str = ares_buf_finish_str(buf, &strs->cache_str_len);
```

要点：

1. **拼接不涉及任何长度字节**。长度字节在 parse 阶段已被消费，这里只是把
   各串 payload 首尾相接，所以拼接结果与 RDATA 边界无关——边界问题在
   parse 阶段已经决定了链表中有什么。
2. **拼接结果没有分隔符**，`"ab" + "cd"` → `abcd`，`len = 4`。这与
   RFC 7208/1035 的 TXT 语义一致（多个 character-string 在应用层拼接），
   但也意味着拼接后无法还原分段。
3. **缓存**：`cache_invalidated` 标志 + `cache_str` 缓存
   （`:206-211` / `:228-235`），任何
   `add/swap/del` 都会置脏（`:103/:122/:137`）。
4. **失败语义**：`ares_buf_finish_str()` 失败时返回 `NULL` 且 `*len` 已被
   置 0（`:200`），调用方拿不到 `ENOMEM`。空内容时返回
   非 `NULL` 的 1 字节缓冲区 + `len == 0`（依赖
   `ares_buf_ensure_space(buf, 1)`，`ares_buf.c:405-408`）。这是
   issue #1386 的同一族问题（"empty DNS string 的 finish 失败"），
   与边界无关。

**关键结论**：拼接接口的"剩余长度"处理是"N/A"——它不解析，只拷贝。
如果有人因为 `get_bin()` 返回的串里出现邻居字节而怀疑拼接接口，真正该查
的是 parse 阶段（§3），不是这里。

## 6. 畸形应答何时会读到相邻记录

满足以下全部条件时，payload 会跨过 RDLENGTH：

1. 解析路径是 TXT（走 `ares_dns_multistring_parse_buf()`）；
2. 某个长度字节 `len` 满足 `0 < len` 且
   `RDATA 剩余 < len <= 报文剩余`（报文后面确实有字节，即本 RR 不是
   payload 的最后一段）；
3. 越界后的总消费量 `processed_len` 仍 `<= rdlength`（此时
   `ares_dns_parse_rr()` 的事后总闸不会触发），或者调用方直接使用内部
   helper 而不经过 `ares_dns_parse_rr()`。

**公共 API 的实际情况（实测）**：

| 情形 | helper 是否越界 | 公共 API 表现 |
|---|---|---|
| D 报文在 RDATA 尾结束 | 否（无字节可读） | `EBADRESP` |
| E/F 越界且总消费量 > RDLENGTH | **是** | `EBADRESP`（事后总闸兜住，无污染输出） |
| G 声明的 RDLENGTH 恰好覆盖邻居头部 | 否（按声明读） | **成功，邻居头部成为 TXT payload** |
| 直接调用 `ares_dns_multistring_parse_buf()` | **是** | helper 返回 `ARES_SUCCESS` + 污染数据（见 §7 的反向测试输出） |

因此准确表述是：

- **对 `ares_dns_parse()` 的调用方**：不会拿到越界的 TXT 数据，
  但会看到"畸形报文被整体拒绝"，且拒绝的判据是事后总消费量，
  属于 defense-in-depth 而非边界语义；
- **对内部 helper 的调用方**（semi-public，`src/lib/record/` 内部；
  以及未来任何复用它解析 RDATA 列表的代码）：完全没有边界保护，
  helper 会读到相邻记录，且返回成功；
- **G 类报文**：无论走哪个入口，语义上都是"发送方声明 RDATA 包含这些
  字节"，解析器无法也不应该猜测；但这提醒我们 **RDLENGTH 是唯一可信
  边界**，长度字节不能越过它。

## 7. 最小修复

只收紧 `ares_dns_multistring_parse_buf()` 的逐段检查，与同文件族的
`ares_buf_parse_dns_binstr_int()` 保持一致。**不改变任何合法 TXT 的
结果**：所有 `len <= RDATA 剩余` 的输入走原路径。

```diff
--- a/src/lib/record/ares_dns_multistring.c
+++ b/src/lib/record/ares_dns_multistring.c
@@ -261,11 +261,23 @@
   }
 
   while (orig_len - ares_buf_len(buf) < remaining_len) {
+    size_t used_len;
+
     status = ares_buf_fetch_bytes(buf, &len, 1);
     if (status != ARES_SUCCESS) {
       break; /* LCOV_EXCL_LINE: DefensiveCoding */
     }
 
+    /* RFC 1035 3.3: TXT-DATA is one or more <character-string>; each string,
+     * including its length octet, must fit inside the enclosing RDATA.  A
+     * length octet reaching past RDLENGTH is malformed -- do not borrow bytes
+     * from the following record.  Mirrors ares_buf_parse_dns_binstr_int(). */
+    used_len = orig_len - ares_buf_len(buf);
+    if ((size_t)len > remaining_len - used_len) {
+      status = ARES_EBADRESP;
+      break;
+    }
+
 
     /* When used by the _str() parser, it really needs to be validated to
      * be a valid printable ascii string.  Do that here */
```

为什么是这个位置而不是别处：

- **不改 `ares_dns_parse_rr()`**：事后总闸已经存在，且它对非 TXT 类型
  （单串/定长类型）仍然有用；在这里加边界属于"隔离子缓冲区"的更大改动，
  不是最小修复。
- **不改 `ares_buf_fetch_bytes_dup()`**：它是通用 buffer API，不知道
  RDATA 概念；给它加参数会污染整个 `ares_buf` 契约。
- **复用现有 helper 不够**：`ares_buf_parse_dns_binstr_int()` 只解析单个
  `<character-string>`，而 TXT-DATA 是列表；把它改成"循环调用"会改变
  `ares_buf_parse_dns_binstr()` 的公开语义（`src/lib/include/ares_buf.h`
  里它用于 OPT/其它单串场景），超出最小修复范围。
- `used_len` 用 `size_t`，`len` 是 `unsigned char`，`-Wconversion`
  下显式 `(size_t)` 转换；`remaining_len - used_len` 在循环条件保证
  `used_len < remaining_len` 的前提下不会下溢。

修复后实测（同一套 harness）：

| 场景 | 修复前 | 修复后 |
|---|---|---|
| A/B/C/T/U/J/K/L/M/N（合法） | 全部成功，结果不变 | **完全一致** |
| D/E/F/S（越界/截断，公共入口） | `EBADRESP` | `EBADRESP`（判据从"事后总闸"变为"逐段检查"） |
| 内部 helper + D/E 布局 | `ARES_SUCCESS`，`consumed=8 > rdlength=3` | `ARES_EBADRESP`，`consumed=3`，`*strs == NULL` |
| G（声明覆盖邻居头部） | 成功，邻居头部成为 payload | 成功，**行为不变**（声明本身就是这么写的） |

全量测试（`./build/bin/arestest -4 --gtest_filter='-*Live*'`）：
**763 个用例全部通过**（含新增 §8.1 的 2 个 + §8.2 的 1 个）。

## 8. 回归样本

helper 层用例**打补丁前失败、打补丁后通过**；公共入口用例是防回归护栏
（修复前后都通过，锁定"公共 API 继续 fail-closed"）。

### 8.1 helper 层（`test/ares-test-internal.cc`）

直接喂 RDATA 边界为 3、其后紧跟 12 字节"邻居 RR 头部"的缓冲区：

```c
/* ares_dns_multistring_parse_buf() 是 TXT/RDATA 字符字符串的共用 walker。
 * 它的 remaining_len 是本 RDATA 长度；长度字节不得让它越过该边界。 */
TEST_F(LibraryTest, DNSMultistringParseStopsAtRdlength) {
  /* "a" 后面跟一个声称 5 字节的长度字节，但 RDATA 只剩 3 字节。
   * 后面 12 字节是一条 RR 的头部。 */
  static const unsigned char wire[] = {
    0x01, 'a', 0x05,
    0xc0, 0x0c, 0x00, 0x10, 0x00, 0x01, 0x00, 0x00, 0x00, 0x64, 0x00, 0x02
  };
  ares_buf_t             *buf  = NULL;
  ares_dns_multistring_t *strs = NULL;

  buf = ares_buf_create_const(wire, sizeof(wire));
  ASSERT_NE(nullptr, buf);

  EXPECT_EQ(ARES_EBADRESP,
            ares_dns_multistring_parse_buf(buf, 3, &strs, ARES_FALSE));
  EXPECT_EQ(nullptr, strs);
  /* 缓冲区不得被推进越过声明的 RDATA */
  EXPECT_GE(ares_buf_len(buf), sizeof(wire) - 3);

  ares_buf_destroy(buf);
}
```

不打补丁时的失败输出（实测）：

```
[ RUN      ] LibraryTest.DNSMultistringParseStopsAtRdlength
...:2866: Failure
Expected equality of these values:
  ARES_EBADRESP
    Which is: 10
  status
    Which is: 0
...:2867: Failure
Expected equality of these values:
  nullptr
    Which is: NULL
  strs
    Which is: 0x56e8fb8d9ae0
...:2870: Failure
Expected: (ares_buf_len(buf)) >= (sizeof(wire) - 3), actual: 7 vs 12
[  FAILED  ] LibraryTest.DNSMultistringParseStopsAtRdlength
```

（`ares_buf_len` 从 12 掉到 7，即 helper 多吃了 5 字节邻居数据。）

配套的**正向**样本，保证修复没有把合法边界卡死：

```c
/* 恰好边界：255 字节 payload + 长度字节 = RDATA 长度 256，必须成功。 */
TEST_F(LibraryTest, DNSMultistringParseExactRdlength) {
  unsigned char           wire[256];
  ...
  wire[0] = 255;
  memset(wire + 1, 'A', 255);
  ASSERT_EQ(ARES_SUCCESS,
            ares_dns_multistring_parse_buf(buf, 256, &strs, ARES_FALSE));
  EXPECT_EQ((size_t)1, ares_dns_multistring_cnt(strs));
  EXPECT_EQ((size_t)255, len);
}
```

两个用例都要包在 `#ifndef CARES_SYMBOL_HIDING` 内（与文件内既有内部
API 测试一致，共享库隐藏符号时不编译）。

### 8.2 公共入口层（`test/ares-test-parse-txt.cc`）

用原始字节构造（`DNSTxtRR` 帮不上忙，因为它的 RDLENGTH 由字符串长度
自动算出，无法制造"长度字节超出 RDLENGTH"）：

```c
/* 长度字节越界、后面还跟一条合法 TXT RR：不得把后一条记录折进前一条。 */
TEST_F(LibraryTest, ParseTxtStringOverflowsRdlengthThenNextRecord) {
  std::vector<byte> data;
  std::vector<byte> rdata1 = {0x01, 'a', 0x05};   // 声称 5 字节，实际 0
  std::vector<byte> rdata2 = {0x01, 'Q'};

  BuildRawTxtResponse(&data, {rdata1, rdata2}, {3, 2});

  struct ares_txt_reply *txt = nullptr;
  EXPECT_EQ(ARES_EBADRESP,
            ares_parse_txt_reply(data.data(), (int)data.size(), &txt));
  EXPECT_EQ(nullptr, txt);

  struct ares_txt_ext *ext = nullptr;
  EXPECT_EQ(ARES_EBADRESP,
            ares_parse_txt_reply_ext(data.data(), (int)data.size(), &ext));
  EXPECT_EQ(nullptr, ext);

  ares_dns_record_t *dnsrec = nullptr;
  EXPECT_EQ(ARES_EBADRESP, ares_dns_parse(data.data(), data.size(), 0, &dnsrec));
  EXPECT_EQ(nullptr, dnsrec);
}
```

（`BuildRawTxtResponse()` 是测试内约 20 行的辅助函数：写头 + question +
逐 RR 写 `c0 0c` owner、type/class/TTL、**显式 RDLENGTH**、原始 RDATA。
`PushInt16/PushInt32` 已由 `dns-proto.h` 提供；插入重复字节用
`data.insert(data.end(), str, str + n)`。）

**注意**：这一层用例在**修复前后都通过**——因为
`ares_dns_parse_rr()` 的事后总闸（`processed_len > rdlength`）已经兜住了
这类布局。它的价值是**锁定"公共 API 必须继续 fail-closed"**这个不变量，
防止将来有人把总闸挪走或改成"容忍尾部"。真正能区分修复前后的是 §8.1
的 helper 层用例。

## 9. 建议

1. **采纳 §7 的一处修复**（6 行有效代码 + 注释），把边界检查放到它该在
   的地方，让 helper 自己守住契约，而不是依赖调用方的事后总闸。
2. **采纳 §8.1 的两个 helper 用例**（负向 + 正向）；§8.2 的公共入口用例
   可作为防回归护栏一并加。
3. **另行决策（不在本次修复内）**：
   - `ares_parse_txt_reply()` 在"扫不到 TXT"时返回 `ARES_SUCCESS` +
     `NULL`（P/R 行）与"无答案"返回 `ENODATA`（Q 行）的自相矛盾；
   - `get_bin()` 对"0 个字符串"返回 `NULL`、对"1 个空字符串"返回
     非 `NULL`+`len 0`，调用方无法区分；
   - 大量空/短字符串的内存放大（§4.4，约 49×/144×），属于
     `ARES_DATATYPE_ABINP` 的存储模型问题；
   - 空 RDATA 让**整条报文**失败（§4.3），可按 RFC 1035 §3.3
     "one or more" 明确写成文档化行为。
4. **不要**顺手"放宽"解析器去接受越界长度字节。RFC 1035 §3.3 要求
   每个 `<character-string>` 落在 TXT-DATA 内，收紧是合法的；
   而**发送侧**已有正确的重新分块（`ares_dns_write_binstr()`，
   `ares_dns_write.c:225-261`，超过 255 字节自动切段），
   所以合法 peer 不受影响。

## 附录：复现方法

```sh
cmake -DCMAKE_BUILD_TYPE=DEBUG -DCARES_BUILD_TESTS=ON \
      -DCARES_STATIC=ON -DCARES_SHARED=OFF -G Ninja -B build
ninja -C build
./build/bin/arestest -4 --gtest_filter='LibraryTest.DNSMultistringParse*:LibraryTest.ParseTxtString*'
```

本文 §4 表格的数据来自两个独立 C 程序（链接 `build/lib/libcares.a`）：

1. **公共入口矩阵**：按 §4 各行的字节布局拼报文，逐用例打印
   `ares_dns_parse` 状态 / 答案 RR 数 / `abin_cnt` / `get_bin()` 的
   `combined_len`，以及 `ares_parse_txt_reply`/`_ext` 的返回码、节点数、
   payload 总字节数；
2. **helper 观测**：用 `ares_buf_create_const()` 包住同一段 RDATA + 邻居
   字节，直接调 `ares_dns_multistring_parse_buf()`，打印返回码与
   `consumed - rdlength`（即是否越过声明边界）。

两个程序分别在**未打补丁**的 `HEAD` 与**打了 §7 补丁**的同一份源码上
各跑一遍，差异即 §7 的"修复前/后"表。§4.5 的 legacy 语义差异另用
`src/lib/legacy/ares_parse_txt_reply.c` 的同一报文验证。
