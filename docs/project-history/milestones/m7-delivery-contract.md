# M7 投递 Worker、传输与本地收件器合同

状态：设计稿，M6 已启动但仍在唯一真实验收窗口。此文件不授权 M7 产品代码、SQL010、部署、后台发送或外部账户消息。M6 的现有进程、网络、监控与门户密钥材料本轮均不变。

依据：`M7-implementation-contract.md`、`M7-storage-contract.md`、现有 Kong outbound 的 DNS pin/异步 prepareSend/同步 beforeSend，以及 M6 实际门户网络修复。M7 传输不复用 Kong Admin 的 host allowlist，也不调用任何 Kong Enterprise Event Hooks 端点。

## 文件与所有权

DevOps 拟独占 `apps/console-api/src/modules/event-delivery/`：`event-delivery.module.ts`、`delivery-worker.service.ts`、`delivery.types.ts`、`delivery-policy.service.ts`、`http-delivery.transport.ts`、`smtp-delivery.transport.ts`、`delivery.providers.ts`。Worker 没有公共控制器，没有接受任意 URL 或任意 payload 的 HTTP 接口。

部署拟独占 `deploy/compose/compose.notifications-test.yml`、`deploy/event-receivers/{http,smtp,control,server}.mjs`、`deploy/scripts/prepare-event-receivers.mjs`、`verify-event-delivery-deployment.mjs` 及既有 stage/env/secret-scan 工具的明确增量。本地收件器只有 test profile，默认生产 Compose 不启动它们、不播种外部 URL。既有 `nodemailer@10.1.0` 与 Node22 已可用；优先不新增依赖，不使用关闭 TLS 校验的测试捷径。

Storage 独占 `modules/event-core/delivery-repository.service.ts` 的 `DeliveryRepositoryService`（claim/intent/heartbeat/finalize）、独立 OutboxRepository 的 fanout 与 SQL010；Root 独占 EventAccess 当前权限与历史源范围匹配。Kong/Workflow 独占 channel/subscription 的真实 IAM/workflow handler、版本、加密输入和审批。Worker 不自行恢复开发者、HTTP session 或万能管理员身份。

## 最小接口提案

方法与认领类型按 `M7-event-core-interface.md` 第6节冻结；实现仍等待M6提交与Root明确释放：

```ts
interface DeliveryClaim {
  deliveryId:string; eventId:string; clusterId:string; workspaceId:string;
  deliveryKind:'subscription'|'test';
  subscriptionId:string|null; subscriptionRevision:number|null;
  channelId:string; channelRevision:number; credentialGeneration:number;
  creatorId:string; leaseOwner:string; leaseGeneration:number;
  leaseUntil:string; attemptNo:number; idempotencyKey:string;
  // Only server-built, immutable, digest-verified DTO; no native config.
  payloadSafe:DeliveryPayload; payloadDigest:string;
}
interface EventAccess {
  assertDeliveryCurrent(claim:DeliveryClaim):Promise<{
    actorId:string; permissionVersion:string;
    subscriptionRevision:number|null; channelRevision:number;
    credentialGeneration:number; sourceProofDigest:string;
  }>;
}
interface DeliveryRepositoryService {
  claimDue(input:{owner:string;limit:number;leaseMs:number}):Promise<DeliveryClaim[]>;
  commitSendIntent(claim:DeliveryClaim):Promise<boolean>;
  assertLeaseCurrent(claim:DeliveryClaim):Promise<void>;
  renewLease(claim:DeliveryClaim,leaseMs:number):Promise<boolean>;
  finalize(claim:DeliveryClaim,outcome:DeliveryOutcome):Promise<boolean>;
  recoverExpiredIntents(input:{limit:number}):Promise<number>;
  // Trusted worker only; recheck exact claim/lease/generation before and after decrypt.
  loadChannelSecrets(claim:DeliveryClaim):Promise<ChannelMaterials>;
}
interface PreparedDelivery {
  // May await DNS/TLS; must not transmit Authorization, recipients or message.
  send(input:{prepareSend:()=>Promise<void>;beforeSend:()=>void;
    signal:AbortSignal}):Promise<DeliveryOutcome>;
  close():void;
}
```

`EventAccess` 从服务端加载真实、active 的渠道作者以及订阅/测试作者，两人均需当前 whole-workspace `events.write`、完整源事件 `events.read`、同 grant 的 CID/WID/实体/标签条件。源使用发生时的可信范围，不读已删对象、不按当前标签改挂历史。channel/subscription inactive、删除、revision/generation 改变、任一作者停用或撤权立即停止旧投递并诚实进入 `paused_authority`。测试投递没有虚构订阅，其 subscription ID/revision 均为NULL。接口返回的是当前证明，不是可由客户端传入的授权 flag；worker 不能使用历史 JWT 或 session 代替它。

公开 `DeliveryOutcome` 仅含 `outcome:succeeded|failed|uncertain`、固定 `errorCode`、HTTP 状态（若适用）、耗时、`retryable`、有界 `retryAfterMs` 和明确 `sendStarted`。没有目标 URL、响应正文、认证头、原始异常或 SMTP 会话文本。

## Durable 意图与最终发包顺序

1. 以 `FOR UPDATE SKIP LOCKED` 有界 claim；提交认领事务。过期旧 sending intent 先补一次 immutable uncertain attempt，再认领下一 attempt；不能把发送历史改成“未尝试”。
2. 加载当前 authority/channel/subscription/源 DTO，检查 tuple 和 payload digest；提交固定 attempt_no/lease_generation/send intent。DB 行锁不跨网络等待。
3. 执行完整 DNS、目标安全与 provider 准备；每个 await 后检查本 callback 的 closed/lease/deadline/AbortSignal。解析全部地址，只选择已通过的一个地址 pin 到当前 socket，后续不能重新解析默认 DNS。
4. DNS/prepare await 完成后，再由 EventAccess 读取当前权限与配置 revision/generation，并由 Repository 核验租约。异步检查与同步 beforeSend 分离；最后一次 await 之后，beforeSend 和实际请求创建/写入处于同一同步调用栈。
5. 同步 fence 检查 callback 未关闭、租约/授权证明属于本次 claim、预算未过期、generation/revision 未换、signal 未中止。租约失效、worker shutdown 或异常 continuation 都永久关闭该 capability 并销毁 socket，不允许迟到发包。
6. 完成后一次 INSERT append-only attempt，再以同 lease generation CAS 推进队列。旧 worker 不能改写新认领状态；已存在的 uncertain outcome 不因迟到 ACK 更新为成功。heartbeat 丢失后即关闭传输。

SMTP 有额外协议 await：连接与 TLS/EHLO 阶段不发凭证或业务正文；TLS 校验证明后、AUTH 前以及 DATA 正文前均重走 fresh prepareSend + 同步 fence。不能在 `nodemailer.sendMail()` 外仅做一次检查，然后放任其隐藏的 DNS/TLS/login await 绕过最后授权。采用可测试的 SMTP connection adapter 或明确受控状态机，具体实现由独立 review 核实，而非假设库内部有此 fence。

队列默认 claim<=20、网络并发<=2、lease30秒、heartbeat5秒；HTTP 总预算5秒、SMTP总预算15秒。callback/transport总预算应小于 lease，不能无界 DNS/socket/read 等待。暂停、shutdown 不改写已提交事件或删除队列。

## 出站政策与秘密

单独 `EVENT_DELIVERY_ALLOWED_HOSTS` 精确 `hostname:port` allowlist，默认空；不继承 Kong/Prometheus/Loki/认证提供方列表，不提供 wildcard。生产仅 HTTPS Webhook/Slack/飞书及证书校验的 SMTP。URL 拒绝 userinfo、fragment、控制字符、编码分隔符、非标准 scheme、任意 redirect；query 默认禁止，token 路径整体视为秘密。全 DNS 结果拒绝 unspecified、loopback、link-local/metadata、multicast、IPv4-mapped IPv6及任何已注册控制面 IP。

保护集合覆盖 BFF 所有接口、全部集群 Admin、各独立 Kong DB、ConsoleDB/Redis、Console/Portal 两接口、Prometheus/Loki、collector 所有接口及测试收件器。普通 Service/Target/http-log 不得把通知接收器当原生代理旁路；事件传输仅对 operator 注册的精确 receiver authority 存在独立最小例外。合法企业私有业务目标可显式登记，不能笼统封禁整个 RFC1918 网段。

DNS 返回 mixed safe/protected、空集合、地址换绑均拒绝；HTTPS 保留原 hostname/SNI/证书名称，socket pin 已验证 IP。不得跟随重定向或自动重放 POST。HTTP 请求仅固定 POST、固定 Content-Type、服务器 User-Agent/Idempotency-Key/Event-ID 及明确认证；禁止租户覆写 Host/Connection/Content-Length/Transfer-Encoding/Cookie/转发头。

channel endpoint/auth 由 SecretService 按 channel ID/CID/WID/generation/purpose 上下文 AEAD 加密；建议 AAD `event-channel:<id>:<cid>:<wid>:<generation>:endpoint|auth`，需与 Kong owner 一次冻结。仅传输 provider 在 RAM 内解密。目标变更不能带旧认证到新 host。SMTP host/port/TLS/CA 为 operator 固定配置，不接受个人渠道指定任意 SMTP server；共享 SMTP 密码只在 API 私有配置，UI只设置有界收件人。SMTP配置未提供时目录真实 unavailable，不伪造成功。

全部日志/attempt/public DTO 仅 UUID、状态码、耗时、固定错误码。URL包括Slack/飞书token路径都不日志；响应正文/SMTP错误句子不会进入公开摘要。原始 body/headers 不落 Docker 日志、本地收件器日志或永久文件。秘密扫描覆盖明文、Bearer、Basic及SMTP AUTH编码。

## Provider 与重试

- Webhook：version1安全 envelope，固定 event/delivery IDs、发生时间、CID/WID、类型/阶段/结果、明确已授权的源 UUID及服务器固定中文摘要。无 before/after、config、credential、私钥、子对象图或任意用户模板执行。内容按UTF-8序列化后最大8KiB；响应最大8KiB，压缩/redirect拒绝。
- Slack：固定 incoming webhook 模板，只发送上述安全摘要与UUID；HTTP200且固定`ok`才 success。原始provider响应不保存。
- 飞书：固定 text 模板，签名secret仅RAM；HTTP200且provider成功code才 success。错误为固定分类，不回显msg或token。
- Email：最多20个语法正确、无CR/LF的显式收件人；固定subject/plain-text，无HTML、附件、任意Header、CC/BCC或外部图片。SMTP implicit TLS或强制STARTTLS，最低TLS1.2、正确servername、rejectUnauthorized=true。服务端不支持STARTTLS、证书错误、TLS断开均fail closed，绝不降级明文AUTH或DATA。

同 delivery 的自动 retry 始终复用稳定 Idempotency-Key。HTTP2xx/providerACK为成功；429/部分5xx等可重试；普通4xx为不可重试。DNS/策略/授权前拒绝是证明没有发送的失败；连接断开/超时/worker崩溃且可能已发送的结果是 uncertain。重试不声称远端未处理。默认指数退避带有界jitter、最多8次/24小时，Retry-After限定合理区间；穷尽后exhausted。手动replay另建显式generation，不更新旧事件/attempt。

Slack/SMTP接收方可能不实现幂等去重，因此至少一次可出现重复通知；稳定Message-ID/Idempotency-Key便于接收者识别，不能宣传 exactly-once。

## 本地实际收件器与部署

拟 `notifications-test` profile 建立 internal `delivery-test`：默认 `172.28.51.0/24`，API`.10`、HTTPS `event-receiver` `.20:9087`、SMTP `event-mail` `.30:2465`。这两个receiver无Admin/storage/frontend/portal/telemetry接口，无host端口；API保留全部既有接口。内部only服务不需要public端口，因此不重复M6 internal-only host publication问题。

receiver使用已缓存Node22、UID1000、readonly/capdrop/NNP/tmpfs，只读绑定公开脚本及独立秘密目录。测试提供独立私有CA及精确SAN `event-receiver`、`event-mail` 的真实TLS证书；API仅在test profile只读加载该CA，始终 `rejectUnauthorized=true`。HTTPS不接受明文入口；本地SMTP固定强制STARTTLS，TLS前仅协议协商，证书和fresh authority通过后才允许AUTH/DATA，禁止降级。秘密目录0700、UID1000文件0400、wx不覆盖。使用独立测试凭证，不复用APP/Portal/metrics/key-auth秘密，不写生产外部账号。

HTTPS receiver固定 `https://event-receiver:9087/hook`，SMTP固定受控测试邮箱；可通过私有tmpfs Unix控制socket设置一次429/5xx/延迟/断开等故障。receiver只记录安全白名单ID、计数、状态、时间及body digest，不保存Authorization、原始URL/query/body/MIME。测试读取通过可信Docker exec只返回安全统计，不开放产品HTTP管理入口。无通用“向任意地址发送”测试按钮。

M7 stage保留所有既有PG/Redis/Kong/Portal/Prom/Loki/collector卷与密钥，不enroll/rotate；若新增API env/network需要重建，记录原因和原连续性基线。只在全量source与隔离PG/离线transport gate通过、Root正式放行后启动worker/localreceivers。M6的私有reference由安全方最终扫描后删除；M7如需当前四用途回归，再走可信current-family捕获，不重新生成或轮换。

## 必须验证的证据

独立本机loopback tests覆盖所有DNS地址混合拒绝、pin/socket无二次解析、redirect、protected各接口、权限/lease/配置在DNS与TLS await期间撤销、迟到continuation零HTTP/AUTH/DATA、TLS/STARTTLS错误无明文降级、响应/正文/时间预算和secret canary不泄漏。隔离PG证明intent先commit、immutable attempt一次insert、过期intent uncertain、CAS与fanout continuation不丢后页。

实际窗口先source+启动/网络/UID门禁，再由Security唯一串行发送本地Webhook/SMTP并核验真实audit→event→delivery→attempt、retry稳定key与receiver安全统计，然后browser/人工UI，最后清理与所有编码秘密扫描。真实外部Slack/飞书/邮件账号缺省未配置时明确记录“未外部联调”，不能把本地模拟报告为已接入外部商用账号。
