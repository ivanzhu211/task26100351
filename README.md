# auditlog — 防篡改审计日志库

纯 Python 标准库实现，存储用 SQLite(WAL 模式)。支持多进程并发追加、
SHA-256 哈希链校验、基于密码学粉碎(crypto-shredding)的 PII 擦除。

## 设计

- **哈希链**:每条entry的哈希 = `SHA256("AUDITLOG1" ‖ prev_hash ‖ 规范序列化(时间, 操作者, 动作, 会话ID, subject_id, nonce, PII密文))`。
  `erased` 标志不参与哈希,因此擦除标记不会改动链。
- **PII 加密**:每个 subject 一把随机 256 位密钥(存 `subject_keys` 表),
  每条 entry 用随机 nonce + HMAC-SHA256 计数器模式密钥流加密 PII。
  随机 nonce 保证链上哈希无法用来确认猜测的 PII 值。
- **erase = 密码学粉碎**:① 先在链上原子提交擦除记录并登记
  `erased_subjects`;② 删除主体密钥(`PRAGMA secure_delete=ON`,字节被覆写);
  ③ 分批(默认 1000 条/事务)把该主体的 entry 标记为 erased,批间其他进程可继续 append;
  ④ `wal_checkpoint(TRUNCATE)` 清除 WAL 中的残留密钥帧。
  任意时刻被 SIGKILL,链仍然可验证;重跑 erase 幂等收敛。
- **erase 后的 append**:主体已擦除时,append 改用内存中的临时密钥加密,
  密钥永不落盘——entry 正常入链,但 PII 不可还原。
- **并发**:所有写操作在 `BEGIN IMMEDIATE` 事务内完成(带 busy 重试),
  多进程 append 严格串行化,链保持线性、不丢条目;verify 在 WAL 快照上流式
  读取(`fetchmany`),不阻塞写入、不把全链读入内存。

## API

```python
from auditlog import AuditLog

log = AuditLog("audit.db")
seq = log.append(actor, action, session_id, subject_id="user-1",
                 pii={"name": "...", "phone": "..."})
head = log.head()                    # (seq, hash),审计员另行记录
log.erase("user-1")                  # 粉碎该主体全部 PII 并留下链上记录
issues = log.verify(known_heads)     # [] 表示通过;否则列出问题(含条目序号)
log.read_pii(seq)                    # 解密 PII;密钥已销毁则返回 None
```

`verify` 能检测:未擦除字段被改动(指出条目序号)、条目删除/插入/换序、
链尾被截到已知 head 之前、entry 处于已擦除状态但链上无该主体的擦除记录。

## 测试

```
python3 -m unittest discover -s tests -v
```

覆盖:多进程并发 append + 中途 erase(条目不丢、过程中的 head 全部可验证、
数据库目录逐字节扫描无 PII 明文)、erase 中途 SIGKILL 后 verify 通过且重跑收敛、
篡改/删除/换序/截断检测、无擦除记录的 erased 状态检测。
