# task26100351
防篡改审计日志库（纯 Python 标准库 + SQLite）。

## 设计

- **哈希链**：每条目的哈希 = SHA-256(前一条哈希 ‖ 本条规范化 JSON)。
  链上承诺的"内容"里，PII 只以**密文**形式出现，因此链本身永远不会
  泄露明文，也无法被用来枚举验证猜测值（如逐个试手机号比对）。
- **PII 加密**：每个数据主体一把 256 位随机密钥，存放在独立小文件
  `keys/<sha256(subject)>.key`；加密为 HMAC-SHA256 计数器模式流加密，
  每条目随机 nonce。
- **擦除 = 密码学粉碎**：`erase` 按崩溃安全顺序执行——
  1. 先把擦除记录追加到链上（幂等）；
  2. 在主体文件锁内设墓碑并覆零删除密钥文件（fsync 文件与目录）；
  3. 分批小事务把该主体条目标记为已擦除（期间其他进程可继续 append）；
  4. checkpoint 收拢 WAL，避免伴随文件残留。
  任意时刻被 SIGKILL，中间状态都能通过 verify，重跑 erase 幂等收敛。
  擦除后对该主体的 append 使用随用随弃的临时密钥，PII 天然不可还原。
- **并发**：append 在 `BEGIN IMMEDIATE` 事务内读取链尾并插入，SQLite
  单写者串行化保证链严格线性；WAL 模式 + busy_timeout 避免锁竞争报错。
- **verify**：流式重放（游标逐行，不载入内存），检查序号连续、prev_hash
  链接、逐条哈希、列与 payload 一致、每个已知 head、链尾未被截断，
  以及"密钥已销毁的主体必须链上有擦除记录"。

## API

```python
from auditlog import AuditLog, Entry

log = AuditLog("path/to/dir")
seq = log.append(Entry(actor="alice", action="update", session_id="s1",
                       subject_id="user-1", pii={"phone": "138..."}))
head = log.head()                 # 审计员另行记录
log.erase("user-1")               # 粉碎该主体全部 PII
log.verify(known_heads=[head])    # 任何篡改都会抛 VerifyError（含 seq）
```

## 测试

```
python3 -m unittest tests.test_auditlog -v
```

覆盖：多进程并发 append 中途 erase（条目不丢、链线性、历史 head 全部
可验证、目录逐字节扫描无 PII 明文）、erase 中途 SIGKILL 后恢复、
字段篡改/删除/插入/换序/截断/无记录粉碎的检测。
