# fpm_oom_generic.py 检测脚本说明

> 脚本：`./fpm_oom_generic.py`（已附在本目录）
> 用途：检测 PHP 端点是否存在 **rfc1867 multipart 元数据放大 OOM**（php2shell 链的根原语，CVE-2026-109618 / CVE-2026-109619）。
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
| 嵌套字段名 `p0[k][k]...[k]` | 每层 ~103B | 每层一棵 HashTable + zval，乘法增长 |
| 空文件名 `filename=""` | 0 字节 body | 不建临时文件、不占 `max_file_uploads` 名额，仍注册 `$_FILES` 元数据 |
| 头部行 `a: b` | 6B/行 | 每行一个 ~180B 的 `mime_header_entry`（30×） |

`post_max_size=8M` 只数 body 体积，元数据不计数 → **~4.8MB 头部洪水**或
**~5.3MB 嵌套名**即可打满默认 `memory_limit=128M`。

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

本脚本主要面向 FPM 场景（OOM + churn 检测）；完整 RCE 链需 mod_php。

---

## 2. 脚本原理

通用发送器：HTTP（经 nginx）或直连 FastCGI（自带协议实现）；构造 multipart body，多线程发送并按响应判定 OOM。支持并发 `-c`、限速 `--rate`、多请求 `-k`。

### payload 一览

| payload | 内容 | 适用 | 预期信号 |
|---|---|---|---|
| `oom`（默认） | 一个 part 带 80 万行 `a: b`（~4.8MB） | 通用 | 响应含 `Allowed memory size`；128M 即可 OOM |
| `nested` | 1000 个空文件名 + 50 层嵌套名 file part（~5.3MB） | FPM | OOM + worker churn（exit 70），无 SIGSEGV |
| `modphp-crash` | 同一 keep-alive 连接两个 chunked 请求：35MB pad + 11MB 嵌套名 → 30MB pad + 11MB 嵌套名 | mod_php | SIGSEGV（11MB 嵌套名在启动解析器被复制 ~10×；chunked 绕过 post_max_size 预检查；docker 日志计数验证） |
| `auto` / `all` | 按 `Server`/`X-Powered-By` 指纹自动选择 | — | nginx → nested；Apache/mod_php → crash 优先 |

### 判定逻辑

- `oom=True`：响应体含 `Allowed memory size`（需 nginx `fastcgi_buffering off;` 才能到达客户端）；
- `suspected_oom`：empty 200 / 502 / 503 / 504 / 连接重置 —— OOM 大概率发生，但 fatal 文本被前端缓冲吞掉；
- FastCGI 模式：在 stdout/stderr 中找 OOM 文本；空输出 / broken pipe = child 启动期即死。

### 对照与探针（排除误报）

- `--control` / 默认 preflight：先发**同体积普通字段** —— 对照组 OK 而 payload OOM ⇒ 放大器成立，排除尺寸限制；`413` ⇒ 被 `client_max_body_size` / `LimitRequestBody` 挡住；
- `--probe-sizes`：递增 body 尺寸探测 413 / 502 / 500 边界；
- PHP 5.x 直连 FastCGI 绕过：`--big-name-mb 26 -n 0 --content-length -1`（负 CONTENT_LENGTH 回绕，读 STDIN 到 EOF，绕过 post_max_size）。

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

临时缓解（均不完整）：
- `session.upload_progress.enabled=0` + 重启 worker；
- `memory_limit=-1`（php_admin_value）+ 容器/cgroup 内存上限；
- 限 `post_max_size`（chunked / FastCGI 负 CONTENT_LENGTH 可绕过）;
- 高频回收 worker（`MaxRequestsPerChild=1` / `pm.max_requests=1`），破坏"同一 worker"条件。

---

## 4. 常用命令

```bash
# 默认：对照 preflight + 小体量 OOM 检测
python3 fpm_oom_generic.py --url http://127.0.0.1:8214/index.php

# 跳过对照
python3 fpm_oom_generic.py --url http://127.0.0.1:8214/index.php --no-control

# 指纹自动选择 payload
python3 fpm_oom_generic.py --payload auto --url http://127.0.0.1:8214/index.php

# 直连 FastCGI
python3 fpm_oom_generic.py --payload oom --fcgi 127.0.0.1:9003 \
    --script /var/www/html/index.php
```

**判读**：`oom=True` ⇒ 未修复（放大器成立）；仅 `suspected_oom` ⇒ 关 nginx 缓冲后复测；对照组也 OOM ⇒ 是尺寸/上限问题，不是本漏洞；全程无 OOM ⇒ 已修复或被前端限制挡住。

---

## 5. 脚本附录（`oom_generic.py`，已附在本目录）

只讲设计取舍，四个入口：`build_body()` 造 payload，`run_nested()` /
`run_modphp_crash()` / `run_control()` / `run_probe_sizes()` 执行。

- **payload 形状**（`filename=""` + 嵌套名 + 空 body）：`filename=""` 绕
  `max_file_uploads=20` 名额且不写临时文件，仍注册 `$_FILES` 元数据；嵌套名
  每层一棵 HashTable（`-d ≤ 60` 贴着 `max_input_nesting_level=64`）；空 body
  把体积压在 `post_max_size=8M` 之下 —— 放大全在内存，不在线上。
- **`a: b` 行可全同 key，groom 字段必须不同名**：漏洞版去重只发生在注册阶段
  （`zend_hash_update` 覆盖），解析期每行照常分配 `mime_header_entry`（6B 换
  ~180B）—— 放大在解析期完成，key 随便重。而 filler 要**存活**占内存，
  必须不同名让全部注册成功。（修复版解析期即去重，此路径已封，见 §3。）
- **三种 payload 各司其职**：`oom`（默认，~4.8MB 头部洪水）只求判定、全 SAPI
  适用、故意不追崩溃；`nested` 走真实 `$_FILES` 路径，FPM 预期 exit 70 churn；
  `modphp-crash` 用**同一条 keep-alive 连接**发两个 chunked 请求 —— prefork
  一条连接固定一个 worker，纯 HTTP 满足"同一 worker"条件，chunked 绕过
  post_max_size 预检查，SIGSEGV 靠 `docker logs` 计数（崩溃时客户端收不到
  东西），且需要新鲜 worker（`--restart-container`）。
- **直连 FastCGI**：自带 FCGI 协议实现，绕过 nginx 缓冲拿可靠判定；发送放
  后台线程是因为 FPM 可能在 body 读完前就退出（先写完再读会死锁）。
  `--content-length -1` 是 PHP 5.x 负长度回绕绕过，配 `--big-name-mb 26`
  用 25/26MiB 的体量边界证明放大器。
- **判定分三档**：OOM 的事实和 OOM 文本能否到达客户端是两回事 —— nginx
  缓冲会把 fatal 吞成 empty 200 / 502，这些记 `suspected_oom` 而非失败；
  可靠信号只有响应体里的 `Allowed memory size`。
- **对照组**：先发同尺寸普通字段。对照组 OK + payload OOM ⇒ 形状相关（放大器
  成立）；对照组也 OOM ⇒ 只是尺寸问题；413 ⇒ 被前端挡住。没有这步，"OOM 了"
  无法和"大请求"区分。
- **`auto` 按指纹选**：crash 链会打脏 worker，不能盲发 —— nginx 只跑 nested，
  mod_php crash 优先，未知 nested 先行 crash 兜底；全发是 `all` 模式。
