# php_oom_generic.py 检测脚本说明

> 脚本：`./php_oom_generic.py`（已附在本目录）
> 用途：检测 PHP 端点是否存在 **rfc1867 multipart 元数据放大 OOM**（php2shell 链的根原语，CVE-2026-109618 / CVE-2026-109619）。
> 默认 payload：`amp` —— **202KiB body（206,807B）放大成 ~128MiB 堆（约 650×）**，打满默认 `memory_limit=128M`；**按目标 PHP 版本自动换算 part 数**（5.x/7.x 的 `$_FILES` 链更少，8.x 的 880 part 在 5.6 上只有 86MB，不会 OOM），并区分 nginx+FPM / Apache mod_php 两种 SAPI 的后果。
> 安全限制：仅允许 `127.0.0.1 / localhost / ::1`，并发 ≤ 32，实验室用途。

---

## 1. 漏洞基本原理

一句话：**multipart 解析器把几 MB 的请求体放大成上百 MB 元数据内存，触发 OOM；
OOM 的 longjmp 跳过清理，留下跨请求的悬空会话指针（UAF）；mod_php 上这根
UAF 指针被逐级抬升为 RCE（php2shell，CVE-2026-109618 / CVE-2026-109619），
FPM 上则退化为 worker churn（DoS）。**

按因果链拆成四层，每层只回答一个问题：

### ① 放大器 —— 为什么几 MB 能打满 128M？

multipart 元数据在内存里的体积远大于线上字节：

| 手法 | 线上字节 | 内存代价 |
|---|---|---|
| 嵌套字段名 `p[]...[k]` | 每层 3B（keylen=1） | 每层一棵 HashTable + zval；带 `filename=""` 时是 **6 条链 = 2448B/层** |
| 空文件名 `filename=""` | 0 字节 body | 不建临时文件、不占 `max_file_uploads` 名额，仍注册 `$_FILES` 元数据 |
| 头部行 `a: b` | 6B/行 | 每行一个 ~180B 的 `mime_header_entry`（30×） |

`post_max_size=8M` 只数 body 体积，元数据不计数 → **~4.8MB 头部洪水**或
**~200KiB 的 amp 嵌套名（63 层）**即可打满默认 `memory_limit=128M`。

#### ①' 调优后的 650× 版本：202KiB 就够了

把上面三种手法叠在一起，并把每一个字节都压到 PHP 能接受的下限，就能把线上
body 压到 **206,807 字节**（< nginx 默认 `client_max_body_size 1m`）而仍然
打满 128M：

| 尺寸项 | 数值 |
|---|---|
| 线上 body | 206,807 B（202.0KiB） |
| part 数 × 每 name 层数 | 880 × 63（`p[]` + 62 × `[k]`） |
| 每 part 线上成本 | 235 B |
| 每层线上成本 | 3 B（`[k]`） |
| 每层内存成本 | **2448 B** = 6 条 `$_FILES` 元数据链 × 408 B |
| 估算堆占用 | 880 × 63 × 2448 = 135,717,120 B ≈ **129.4 MiB** |
| 放大比 | **≈ 650×**（实测峰值 134,099,272 B / 206,807 B ≈ **648×**） |

四步把它从 235,616B/572× 压到 206,807B/648×（`--amp-style max`，也是默认；
`--amp-style safe` 保留旧的 235,616B/572× 形状）：

| 优化 | 改前 | 改后 | 省下 |
|---|---|---|---|
| 嵌套深度 | 57 → 58 层 | **62 → 63 层**（`max_input_nesting_level=64` 的极限） | 每 part 77B 头摊到 63 层 |
| boundary | `----amp500`（10B） | **`B`（1B）** | 9 B/part |
| 顶层索引 | `p0000`（5B） | **`p[]`（3B，append）** | 2 B/part |
| part 头 | `Content-Disposition: form-data; name="…"; filename=""` | **`Content-Disposition:name=…;filename=`** | 13 B/part |

这个 206,807B 是**结构上限**，不是调参运气：

```text
放大比 = 层数 × 2448 / (3×depth + 3 + 47)
      = 63 × 2448 / (3×62 + 3 + 47) = 154,224 / 236 ≈ 653×
```

- 线上渐近极限是 `2448/3 = 816×`（每层只花 3 字节）；
- 63 层是死线：8.4.26 实测 **63 层接受、64 层整条 part 被丢弃**（`max_input_nesting_level=64`）；
- 剩下到 816× 的差距，就是每 part 那 47 字节头部（`--B` + `Content-Disposition:name=` + `;filename=` + CRLF），已经被摊到最薄。

顺带三个实测边界（都反证/印证了「6 条链」模型）：

| 写法 | 线上/层 | 内存/层 | 单层放大 | 结论 |
|---|---|---|---|---|
| `[k]`（字符串键） | 3 B | 2448 B | **816×** | 最优（6 条链各自物化） |
| `[]`（空下标 append） | 2 B | 1306 B | 648× | 更短但更差：append 路径不会复制 6 条链 |
| PHP 7.x / 8.0（`$_FILES` 只有 5 个属性，无 `full_path`） | 3 B | ~2010 B | ~670× | 5/6 的量：同 880 part 不 OOM，要 ~1094 part |
| PHP 5.6（同样 5 条链，但每层结构更小） | 3 B | ~1552 B | ~517× | 880 part 只到 ~86MB，要 ~1416 part |

2448 B/层 的来源是 `filename=""` 这个细节，不是玄学：带 `filename=` 的 part
走 upload 分支，PHP 会给 `name / full_path / type / tmp_name / error / size`
**六条平行链**各物化一遍整个括号路径；去掉 `filename=""`（变普通表单字段）
只剩一条 `$_POST` 链，同形状实测只有 **44.8 MiB（~189×）**，不 OOM。
所以 `filename=""` 是 ×3 的乘数，而不是「为了绕 `max_file_uploads`」的副作用。

三个刻意的「贴着上限」：

| PHP 限制 | 默认值 | payload | 效果 |
|---|---|---|---|
| `max_input_nesting_level` | 64 | 63 层（62 个 `[k]`） | 不触发 nesting 丢弃（64 层就整条丢） |
| `max_input_vars` | 1000 | 880 part（+2 session 字段） | 不触发「Input variables exceeded」截断 |
| `post_max_size` | 8M | 230KiB | 永不触发（放大在元数据，不在字节） |

> 前端的 1MB 限制完全看不到这件事：`client_max_body_size` / `LimitRequestBody`
> 数的是**收到的字节**，而 230KiB 的字节在 PHP request startup 阶段变成
> 129MiB 的 `emalloc`，与 nginx / Apache 的内存、worker 数无关。实测对照：
> 同一个默认 1m 的 nginx 前面，`amp`（230KiB）拿到 `Allowed memory size`，
> 而 5MB 级的旧形状直接 **413**。

> **去重的边界（漏洞版行为）**："重复 key 不重复申请内存"只发生在最后向
> `$_POST`/`$_FILES` **注册**时（`zend_hash_update` 对已有 key 更新既有
> bucket，last-writer-wins）；漏洞版解析期累积的 `mime_header_entry` /
> 嵌套结构在注册**之前**就已按行/按层分配，不受 key 重复影响。修复版把
> 去重提前到了解析期（header 白名单 + 重复丢弃），这条放大路径随之消失。

### ② UAF —— OOM 之后留下了什么？

PHP 内存耗尽时用 `longjmp`（bailout）直接跳出执行流，**跳过全部清理**
（session 模块关闭、RSHUTDOWN）。后果是：

- `PS(id)` / `PS(http_session_vars)` 指向的内存已还回 Zend 堆，
  **但全局指针本身活着**（worker 不退出，下个请求照常读）——
  这就是 use-after-free：**指针悬空 ≠ 指针消失**；
- `send_cookie=1` 等标志位残留，给了 B 请求触发读/析构的入口。

正常请求里 `PS(id)` 在请求结束就被清掉；UAF 状态下它仍指向一块已还回
公共池的内存 —— **释放 ≠ 抹除**，Zend 不清内容，下一请求的分配有资格
落到同一地址。

### ③ 利用链 —— UAF 怎么变成 RCE？（mod_php / php2shell）

A/B 双请求结构：**A 造 UAF（OOM 留悬空指针），B 用 UAF（堆接盘 + 触发）**，
必须在同一 worker（keep-alive 连接固定 prefork worker）。

```
A：解析期 OOM → longjmp 跳过清理
     → PS(id) / PS(http_session_vars) 悬空（UAF）
B：堆 groom —— A 里的 pad/filler 稳定 bin 布局，
     B 用精确尺寸的 forge 字段"接盘"悬空页（命中是 groom 出来的，不是碰运气）
  → PS(id) 走 php_url_encode() → 超长 Set-Cookie 越界读
     → 泄漏 chunk base + libphp 基址（绕过 ASLR）            ← 读原语
  → PS(http_session_vars) 被伪造为指向攻击者控制的存活内存
     （fake HashTable：pDestructor = zif_system）
  → php_session_track_init() → zval_ptr_dtor → zend_array_destroy
     → zend_hash_destroy → pDestructor(...) = system("cmd")  ← 执行原语（RCE）
```

两根悬空指针分工：`PS(id)` 提供泄漏（把 `php_url_encode` 变成任意堆读），
`PS(http_session_vars)` 提供执行（让伪造结构在 session 析构时被解引用）。

### ④ SAPI 差异 —— 为什么 FPM 只是 DoS？

| | mod_php (Apache prefork) | PHP-FPM |
|---|---|---|
| OOM 后 worker | **存活**，跨请求状态保留 | startup 失败 → shutdown → `exit(70)`，状态清空 |
| 后果 | UAF 可达 → 完整 RCE 链 | 同款 payload 只有 worker churn（日志 `child N exited with code 70`、新 child 重启），无 SIGSEGV、非 SIGSEGV 崩溃链 |
| 检测可见信号 | SIGSEGV / 泄漏响应 | exit 70 churn、502 / empty 200 |
| 小 payload 的前端门槛 | `LimitRequestBody` 默认 0（不限）；硬化后常见 1m/2m → 230KiB 仍然过 | `client_max_body_size` 默认 **1m** → 230KiB 仍然过，4.8MB 的 `oom` 洪水则 413 |
| 同 worker 条件 | keep-alive 一条连接固定一个 prefork child（`amp-chain` 靠这个） | 无：child 已死，A/B 前提不成立，脚本默认拒绝并降级为 `amp` |

换句话说：**同一个 230KiB 请求，在 FPM 上是「打崩一个 worker 再重启」，
在 mod_php 上是「崩掉当前请求但在存活的 child 里留下悬空指针」**。
脚本据此分流：`amp` 两种 SAPI 都能跑（判定放大器是否成立），
`amp-chain` 只在 mod_php 上有意义（判定 UAF 是否被 reclaim）。

本脚本主要面向放大器判定；完整 RCE 链需 mod_php，
而 `amp-chain` 只提供「UAF 是否可 reclaim」的探针（命中与 worker/groom 有关）。

---

## 2. 脚本原理

通用发送器：HTTP（经 nginx / Apache）或直连 FastCGI（自带协议实现）；构造 multipart body，按响应判定 OOM。

- `amp` / `amp-chain`：单次请求（链模式为同连接的 A/B 对），按 SAPI 给判定；
- `oom`：多线程发送，支持并发 `-c`、限速 `--rate`、多请求 `-k`。

`amp` 的尺寸在 `amp_plan()` 里先算后发：线上预算（默认 1000KB）与堆占用
估算分开打印，拿到 413 / 无 OOM 时能直接看出是哪一层的问题。

### payload 一览

| payload | 内容 | 适用 | 预期信号 |
|---|---|---|---|
| `amp`（**默认**，`--amp-style max`） | 按版本自动换算 part（8.x 898 / 7.x 1094 / 5.x 1416）+ 63 层嵌套名 file part，**206-332KB** | 通用（nginx/FPM、Apache/mod_php、直连 FastCGI） | 响应含 `Allowed memory size`；FPM 日志 exit 70；不触发 413 |
| `amp-chain` | A=同上（带 PHPSESSID/upload-progress，206,947B）+ B=6.1KiB consumer 探针，**同一条 keep-alive 连接** | 仅 mod_php | A OOM + B 返回 >32B 的 `PHPSESSID`（泄漏）或新 SIGSEGV |
| `oom` | 一个 part 带 `a: b` 头部行（5.x/8.x 80 万≈4.8MB；7.x 自动 120 万≈7.2MB） | 通用 | 响应含 `Allowed memory size`；128M 即可 OOM |
| `modphp-crash` | 同一 keep-alive 连接两个 chunked 请求：35MB pad + 11MB 嵌套名 → 30MB pad + 11MB 嵌套名 | mod_php | SIGSEGV（11MB 嵌套名在启动解析器被复制 ~10×；chunked 绕过 post_max_size 预检查；docker 日志计数验证） |
| `auto` | 按 `Server`/`X-Powered-By` 指纹自动选择 | — | nginx → `amp`；Apache/mod_php → `amp-chain` 再 `amp` |
| `all` | 无条件跑 `amp` + `amp-chain` | — | 两个小 payload 都发；`modphp-crash` 保持显式（需 48MB 级 body） |

### 判定逻辑（每个响应只会有一个 `kind=`，避免自相矛盾）

| kind | 含义 | 颜色 |
|---|---|---|
| `OOM` | 响应体里有 `Allowed memory size` —— 唯一“硬”证据 | 绿 |
| `EMPTY200` | `200` + 0 字节：`display_errors=Off` / 前端缓冲把 fatal 吞了 —— **是症状，不是证据** | 黄 |
| `FATAL500` | `500` 但没有 OOM 文本 | 红 |
| `TOO_LARGE` | `413`：被 `client_max_body_size` / `LimitRequestBody` 挡住 | 红 |
| `UPSTREAM` | `502/503/504`：上游挂了（FPM child 死、代理超时） | 红 |
| `ERROR` | 传输层错误 / 连接被重置 | 红 |
| `OK` | 有 body 的正常响应 | 暗 |

### 输出格式：默认只给「请求 / 返回 / 结论」，`-v` 才给 payload 细节

```
$ python3 php_oom_generic.py --url http://127.0.0.1:8083/index.php
[*] POST http://127.0.0.1:8083/index.php  PHP/8.5  (206.1KiB body)
[*] fields: status=HTTP/FCGI status | bytes=response body size | body=first 160 bytes of the response | note=annotation
[control] status=HTTP 200  bytes=146  req=206.2KiB  body='OK\nPHP_VERSION=8.5.11...'
[request 0001] status=HTTP 200  bytes=150  body='<br />\n<b>Fatal error</b>:  Allowed memory size of 134217728 ...'

[*] verdict: CONFIRMED -- HTTP 200 + "Allowed memory size" in the body
```

输出里自带字段图例（`--no-legend` 可关），两行：

```
[*] fields: status | bytes | kind | body[:160]
[*] kind: OOM="Allowed memory size" in body | EMPTY200=200 with 0 bytes (fatal hidden) | ...
[*] fields: sent=requests | oom=OOM text seen | empty200=200 with 0 bytes | suspected_oom=needs proof | ok=2xx with a body | non200=other status | errors=transport | statuses=code histogram
```

| 字段 | 含义 | 取值 |
|---|---|---|
| `status` | 返回状态 | `HTTP 200` / `HTTP 413` / `HTTP 502` … / `FCGI 0`（FastCGI 应用状态） |
| `request NNNN` / `control` | 行标签：第 N 个探测请求 / 同体积对照 | — |
| `bytes` | 响应体字节数 | `0` = 空 body |
| `body` | **响应体**前 160 字节 | 纯文本（换行等已转义），超长末尾加 `...` |
| `req` | 该行请求的 body 大小 | 人类可读：`206.2KiB` / `4.58MiB` |
| `note` | 附注 | 目前只有 `200 with an empty body: fatal text hidden by the target` |
| `control` | 同体积普通字段的对照请求 | 同样的四个字段 |
| `sent` / `ok` / `non200` / `errors` | 发送数 / 有 body 的 2xx / 非 200 / 传输错误 | — |
| `oom` / `empty200` / `suspected_oom` | 含 OOM 文本 / 200+0 字节 / 需佐证 | 互斥口径，`ok` 不含 empty200 |
| `statuses` | 状态码分布 | 直方图 |

高亮规则（`--color auto` 在 TTY 生效，管道里用 `--color always`）：

| 颜色 | 触发条件 | 含义 |
|---|---|---|
| 暗色 | `2xx` / 正常 body | 正常 |
| 黄 | `bytes=0` 的 200、`note=`、`suspected_oom` | 可疑（fatal 被吞） |
| 红 | `413` / `5xx` / `FCGI ---` / `error=` / `non200` | 异常（请求没进 PHP） |
| 绿 | body 里有 `Allowed memory size`、`verdict: CONFIRMED`、`leak=True` | 命中的发现 |

- 每个响应一行，**每个值都带 key**（`status=` `bytes=` `body=` `note=`），行标签是 `[control]` / `[request 0001]`；不再输出 `kind` 这种内部判定名，OOM/空 body 直接看 `status` + `bytes` + `body` 和结论行；
- **结论里也带上状态**，因为状态本身就是判据的一部分：

| 状态 | 含义 |
|---|---|
| `HTTP 200` + `Allowed memory size` | 真 OOM（PHP 把 fatal 放在 200 的 body 里） |
| `HTTP 200` + 0 字节 | fatal 被吞（`display_errors=Off`/缓冲）—— `LIKELY OOM`，需日志佐证 |
| `HTTP 413` | 前端 body 上限，**根本没到 PHP** |
| `HTTP 502/503/504` | 上游死了（FPM child / 代理），不是 413 也不是 OOM 文本 |
| `HTTP 500` | PHP 出错但没带 OOM 文本 |
| `HTTP 200` + 正常 body | 请求被完整处理 ⇒ 没 OOM（修复版/尺寸不够） |
- `--amp` 的 part 数/wire/堆估算/放大比/SAPI 说明全部只在 `-v/--verbose` 下打印；
- 自动加宽只在真的重试时才多打一行 `[try 2/3]`；
- `--color always` 在管道里也强制高亮。

- **`ok` 只统计“有 body 的 2xx”**：`empty200` 单独一栏，否则汇总会出现
  `ok=1 empty200=1 suspected_oom=1` 这种自相矛盾的行；
- 汇总行之后单独打印 `[*] kinds: OOM=1`，并给出结论段（CONFIRMED / LIKELY /
  INCONCLUSIVE / BLOCKED / 无 OOM）；
- **对照与 payload 用同一套 kind**：如果对照组也是 `EMPTY200`，结论直接降级为
  `INCONCLUSIVE`（“这个目标吞大 body，empty 200 不算放大证据”）；
- `amp`：先发**同体积普通字段**对照（默认），再发放大器；
- `oom=True`：响应体含 `Allowed memory size`（需 nginx `fastcgi_buffering off;` 才能到达客户端）；
- `suspected_oom`：empty 200 / 502 / 503 / 504 / 连接重置 —— OOM 大概率发生，但 fatal 文本被前端缓冲吞掉；
- FastCGI 模式：在 stdout/stderr 中找 OOM 文本；空输出 / broken pipe = child 启动期即死；
- `--docker-container`：额外给出 **exit70**（FPM churn）与 **segv**（mod_php UAF 被解引用）的日志增量，这是 SAPI 层面的硬信号，不依赖前端有没有把 fatal 转发出来。

### 对照与探针（排除误报）

- `amp` 内建对照（默认开启，`--no-control` 关）：发一份**与放大器同线上体积**的普通字段（~206.8KB）—— 对照 OK 而 amplifier OOM ⇒ 形状相关，排除尺寸限制；`413` ⇒ 被 `client_max_body_size` / `LimitRequestBody` 挡住（注意：此时限制已低于 230KiB）；
- `--control`：独立的 `--control-size-mb` 同尺寸对照（旧行为，默认 4.8MB）；
- `--probe-sizes`：递增 body 尺寸探测 413 / 502 / 500 边界；
- PHP 5.x 直连 FastCGI 绕过：`--payload oom --header-lines 1500000 --content-length -1`（负 CONTENT_LENGTH 回绕，读 STDIN 到 EOF，绕过 post_max_size）。

---

## 3. 新的修复

php-src 提交 **`31c0ea7d7f`**（*Avoid state corruption via bailout*），核心两刀：

1. **拆放大器**（`main/rfc1867.c`）：`multipart_buffer_headers()` 只保留
   `Content-Disposition` / `Content-Type` 白名单，**重复 key 解析期直接丢弃**——
   header 洪水的 30× 放大消失；`post_max_size` 改按实测字节数
   （`SG(read_post_bytes)`），chunked / 负 CONTENT_LENGTH 绕过被关闭。
   这就是 8.5.12 同 payload peak 2MB、无 fatal 的原因：**根本没囤积**。
2. **拆 UAF 根因**（`Zend/zend_alloc.c` + `ext/session/session.c`）：
   OOM 不再"fatal + longjmp 跳过清理"，改为延迟 OOM——超软限后解析器每步
   查 `ZEND_HAS_OOM()` 即干净退出，有 userland 帧走 `zend_throw_unwind_exit()`
   正常 unwind（RSHUTDOWN 必然执行）；且上传解析一开始就
   `php_rinit_session_globals()`，上一请求残留的 `PS(id)` /
   `PS(http_session_vars)` 先清零。

**修复版本：8.5.12 / 8.4.27 / 8.3.36 / 8.2.35 及以上。** 差分实测：
`php:8.5.12-apache` 同 payload stage 1 即 `A did not OOM` → 本脚本可兼作
修复验证：**修复版应无 `oom=True`**（机理是放大器被封，不是"OOM 处理得更好"）。

`amp` 是最敏感的修复验证器：修复版在解析期就做去重与限额（不再囤积 header /
嵌套元数据），同 230KiB body 只回 200 `ok`（实测 8.3.36 / 8.4.27 / 8.5.12 均无 fatal）。

临时缓解（均不完整）：
- `session.upload_progress.enabled=0` + 重启 worker；
- `memory_limit=-1`（php_admin_value）+ 容器/cgroup 内存上限；
- 限 `post_max_size`（chunked / FastCGI 负 CONTENT_LENGTH 可绕过）;
- 高频回收 worker（`MaxRequestsPerChild=1` / `pm.max_requests=1`），破坏"同一 worker"条件。

---

## 4. 常用命令

```bash
# 默认：同体积对照 + 500x 放大器（230KiB body，两种 SAPI 通用）
python3 php_oom_generic.py --url http://127.0.0.1:8082/index.php

# 明确指定 amplifier；看 FPM 的 exit 70 churn
python3 php_oom_generic.py --payload amp \
    --url http://127.0.0.1:8082/index.php \
    --docker-container fpm-default-lab-fpm-1

# Apache/mod_php：小体量 A/B（OOM -> UAF -> 泄漏探针）
python3 php_oom_generic.py --payload amp-chain \
    --url http://127.0.0.1:8214/index.php \
    --docker-container p2s-of-8.4.26 --chain-probes 4

# 按目标版本自动换算 part 数（默认 --amp-target-mb 132，即略高于 128M）
#   PHP 8.1+ 2448B/层 -> 898 part；7.x/8.0 2010B/层 -> 1094 part；5.x 1552B/层 -> 1416 part
#   若估算偏小，--amp-retries 2 会按 1.6x / 2.6x / 4x 自动重试（仍受 --amp-budget-kb 限制）
python3 php_oom_generic.py --payload amp --url http://127.0.0.1:8230/index.php   # PHP 5.6

# 目标 memory_limit 不是 128M 时，直接给目标堆大小
python3 php_oom_generic.py --payload amp --amp-target-mb 260 \\
    --url http://127.0.0.1:8214/index.php

# 保守形状（引号 + form-data + 58 层：235,616B/572×），给严格/老 parser
python3 php_oom_generic.py --payload amp --amp-style safe \
    --url http://127.0.0.1:8214/index.php --no-control

# 跳过对照 / 指定线预算（更严的前端限制，如 512k）
python3 php_oom_generic.py --payload amp --amp-budget-kb 512 \
    --url http://127.0.0.1:8082/index.php --no-control

# 指纹自动选择
python3 php_oom_generic.py --payload auto --url http://127.0.0.1:8214/index.php

# 需要看 payload 细节（parts/wire/堆估算/放大比/SAPI 说明）时加 -v
python3 php_oom_generic.py --url http://127.0.0.1:8214/index.php -v

# 直连 FastCGI（绕过 nginx，判定最干净）
python3 php_oom_generic.py --payload amp --fcgi 127.0.0.1:9003 \
    --script /var/www/html/index.php

# 其余 payload：~4.8-7.2MB 头部洪水 / ~48MB 崩溃链
python3 php_oom_generic.py --payload oom    --url http://127.0.0.1:8214/index.php
```

**判读**：`oom=True` ⇒ 未修复（放大器成立）；仅 `suspected_oom` ⇒ 关 nginx 缓冲后复测；对照组也 OOM ⇒ 是尺寸/上限问题，不是本漏洞；全程无 OOM ⇒ 已修复或被前端限制挡住（`amp` 只有 230KiB，被挡说明限制 <230KiB）。

### 实测结果（2026-10-26，本机 docker lab）

| payload | 目标 | body | 结果 |
|---|---|---|---|
| `amp` | nginx 1.30.6（**默认 1m**）+ FPM 8.5.11 | 206,807B | `200` + `Allowed memory size of 134217728` ；FPM 日志 **exit70 +1** |
| `amp` | 同一个 nginx 1m + FPM 8.5.11 | ~206.8KB 普通字段 | 对照：同体积普通字段 → 无 OOM（形状特定） |
| `amp` | Apache 2.4.69 + mod_php 8.4.26 | 206,807B | `200` + 同上 OOM 文本 |
| `amp` | 直连 FastCGI → FPM 8.5.11 (`php:8.5.11-fpm`) | 206,807B | `app_status=0` + OOM 文本；exit70 +1 |
| `amp` | 8.4.27 mod_php / 8.5.12 | 206,807B | `200 OK` / `ok`，**无 OOM**（修复版放大器已封） |
| `amp` | 8.3.35 mod_php / 8.3.36 mod_php | 206,807B | 8.3.35 `200` + OOM；8.3.36 `200 OK` 无 OOM（同一 payload 的差分） |
| `amp` | 8.1.31 / 8.4.26 / 8.3.35 / 8.5.11（全部受影响） | 206,807B | 全部 `oom=True`（同一份最小 body 跨四个分支） |
| `amp` | PHP 5.6.40（5 条链，~1552B/层） | 1416 part / 332KB | **`EMPTY200`（OOM；fatal 在 POST 解析阶段被吞）**；880 part 只到 ~86MB，不 OOM |
| `amp` | PHP 7.0.33 / 7.4.33（5 条链，~2010B/层） | 1094 part / 257KB | **`EMPTY200`（OOM）**；880 part 只到 ~111MB，不 OOM |
| `amp` | PHP 7.4.33 同形状 | 880 part → 200 `ok` | 印证：只看 part 数不看版本会误判为“已修复” |
| `amp-chain` | Apache + mod_php 8.4.26 | A=206,947B / B=6,168B | A `oom=True`、`same_conn=True`；B 无 Set-Cookie（探针未命中，正常） |

复现「默认 1m 的 nginx 前，`amp` 通过而大 body 413」：

```bash
# FPM 容器（lab 里已有 fpm-default-lab-fpm-1 / 端口 8082 的 nginx），
# 再起一个**不写 client_max_body_size** 的 nginx（默认 1m）指向同一 network：
cat > /tmp/nginx1m.conf <<'CONF'
server {
    listen 80;
    root /var/www/html;
    index index.php;
    location ~ \.php$ {
        include fastcgi_params;
        fastcgi_param SCRIPT_FILENAME /var/www/html$fastcgi_script_name;
        fastcgi_pass fpm:9000;
        # 故意不写 client_max_body_size -> nginx 默认 1m
    }
}
CONF
docker run -d --name nginx-1m --network fpm-default-lab_default \
  -p 127.0.0.1:8083:80 \
  -v /tmp/nginx1m.conf:/etc/nginx/conf.d/default.conf:ro nginx:stable

python3 php_oom_generic.py --payload amp --url http://127.0.0.1:8083/index.php  # 200 + OOM
python3 php_oom_generic.py --payload oom --url http://127.0.0.1:8083/index.php  # 413 (4.8MB body)
```

---

## 5. 脚本附录（`php_oom_generic.py`，已附在本目录）

只讲设计取舍。新的入口：`amp_plan()` 算尺寸，`build_amp_body()` 造放大器，
`build_amp_consumer()` 造 B 探针，`run_amp()` / `run_amp_chain()` 执行。
旧入口保留：`build_body()` + `run_header_flood()` / `run_modphp_crash()` /
`run_control()` / `run_probe_sizes()`。

- **`amp_plan()` 先把「线上预算」和「堆占用」分开算**：
  `wire = fixed + parts × per_part + close`，
  `est_heap = parts × (depth+1) × 2448`。默认 880 × 63 × 2448 =
  129.4MiB，`per_part = 235B`，比值 ~650×。`--amp-budget-kb`（默认 1000）
  会**反向缩减 parts** 以适配更严的前端；`--amp-parts/-depth/-keylen`
  可重标定；预算紧到算不出 OOM 时会提示（est_heap < 128M）。
- **`--amp-style max|safe` 是两种“语法花费”**：`max` 用
  `Content-Disposition:name=…;filename=`（无引号、无 `form-data`、冒号后无空格）、
  1 字节 boundary、`p[]` append 索引、62 段 `[k]`（63 层）—— 每 part 235B。
  `safe` 是带引号的 `form-data; name="…"; filename=""`、4 位定宽索引、
  20 字节 boundary、57 段（58 层）—— 每 part 248B。两者都能打满 128M，
  `max` 省 12% body；实测两种形状在 8.1/8.3/8.4/8.5 上都被同一个 parser 接受。
- **为什么停在 63 层**：`max_input_nesting_level=64` 是硬线，实测 63 层接受、
  64 层整条 part 被丢弃（不报错、只是不注册）。所以放大比的上限是
  `63 × 2448 / (3×62 + 50) ≈ 653×`，而渐近极限是 `2448/3 = 816×`；
  差的 160× 全是每 part 那 47 字节头部。
- **两个反直觉的实测**：`[]`（2B/层）比 `[k]`（3B/层）短，但只换来
  1306B/层（648×/层），因为 append 路径不会把六条链各物化一遍；
  PHP 7.x/8.0 的 `$_FILES` 只有 5 个属性（无 `full_path`），同一份 880-part
  body 只到 ~111MB、**不 OOM**（要 ~1094 part）；PHP 5.6 只有 ~1552B/层，
  要 ~1416 part —— 这正好反向验证了“每层链数”的模型。
- **三个乘数叠在一起才是 650×**：`filename=""`（→ `$_FILES` 六条链，×3）、
  嵌套名（每 3 线上字节 → 2448B 堆）、每 part 空 body（不碰
  `post_max_size`）。只留嵌套名而不要 `filename`，同形状只有 ~45MiB：
  这组对照是「放大器成立」和「只是请求大」的区分线。
- **贴边而不破边**：depth 62/63 层 < `max_input_nesting_level=64`；
  880 part (+2 session 字段) < `max_input_vars=1000`。故意不触发 PHP 自己的
  拒绝路径——被拒的请求不 OOM，也留不下 UAF（64 层就是这条线）。
- **part 数按目标版本算，不写死**：`$_FILES` 的属性个数决定每层链数
  （8.1+ 六个 = 2448B/层；8.0/7.x 五个 ≈ 2010B/层；5.x 五个 ≈ 1552B/层）。
  `--amp-target-mb`（默认 132）+ `--amp-bytes-per-level`（0=自动）+
  `--amp-retries`（默认 2，按 1.6x/2.6x/4x 加宽重试）三者配合，让同一份
  payload 在 5.6/7.4/8.x 上都能打到 OOM，而不是在 5.6 上悄悄只到 86MB。
  标定必须用**干净的 worker**：mod_php 子进程被前一次 OOM 污染后会复用空闲
  chunk，看起来能便宜 ~4 倍（早期把 7.x 误标成 ~540B/层就是这个原因）。
- **`amp` 先发同体积对照**：对照（普通字段，同 ~206.8KB）不 OOM、
  amplifier（206,807B）OOM，才能排除「尺寸/上限」解释；若对照也 OOM 或
  收到 413，说明问题不在放大器。
- **`amp-chain` 的 A/B 共用一条 keep-alive 连接**（Content-Length，
  不是 chunked）：prefork 把一条连接固定给一个 child，B 才可能落在被 A
  毒化的 worker 里。A 里必须带 `PHPSESSID`/`PHP_SESSION_UPLOAD_PROGRESS`，
  否则 OOM 不会发生在 session 半初始化时，悬空指针不会留下。
- **B 是探针，不是保证命中的 weapon**：形状（filler 数 / forged length）
  来自 Alpine 4-worker 校准，换 image 就要重调；`--chain-probes` 提供
  8 组 groom 变体扫一遍。硬信号不依赖命中：
  `--docker-container` 统计 **exit70**（FPM churn）与 **SIGSEGV**
  （mod_php UAF 被解引用）。
- **`amp-chain` 默认拒绝 nginx 前端**：FPM 的 OOM 发生在 request startup，
  child 直接 `exit(70)`，PS(id)/`http_session_vars` 随进程消失，
  B 没有任何东西可 reclaim。确认前端后面其实是 mod_php 时用
  `--force-chain`。
- **`auto` 按指纹分流**：nginx → `amp`（跳过 chain）；
  Apache/mod_php → `amp-chain` 再 `amp`；FastCGI → `amp`（无 keep-alive
  固定 worker 的前提）。`all` = `amp` + `amp-chain`，
  旧的 `modphp-crash`（~48MB chunked）保持显式。
- **直连 FastCGI**：自带 FCGI 协议实现，绕过 nginx 缓冲拿可靠判定；发送放
  后台线程是因为 FPM 可能在 body 读完前就退出（先写完再读会死锁）。
  `--content-length -1` 是 PHP 5.x 负长度回绕绕过，配 `--header-lines
  1500000` 可以发送 >8MiB 的头部洪水。**连接失败现在不再抛异常**，
  而是记一条 err。（这是本次顺手修的：以前 `send_fcgi()` 在
  `create_connection` 失败时直接抛 `ConnectionRefusedError`。）
- **判定分三档**：OOM 的事实和 OOM 文本能否到达客户端是两回事 —— nginx
  缓冲会把 fatal 吞成 empty 200 / 502，这些记 `suspected_oom` 而非失败；
  可靠信号只有响应体里的 `Allowed memory size`，以及
  `--docker-container` 的 exit70/SIGSEGV 增量。
- **没有 `filename` 就不是同一个 payload**：它既是 ×3 乘数（六条 `$_FILES`
  链），也是 `max_file_uploads` 的绕道；删掉它后即使 depth/parts 不变，
  也只会得到 ~45MiB（不 OOM）。
