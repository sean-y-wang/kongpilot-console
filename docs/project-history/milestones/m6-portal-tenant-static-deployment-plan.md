# M6 门户租户深链：仅静态部署计划

状态：SOURCE ONLY / ACTUAL HOLD。Portal产品源码已冻结；两次before停止及唯一获批只读诊断完整保留，尚未构建Portal。首次为冻结清单覆盖不一致，第二次在business-first读取中报GRANT_UNAVAILABLE；诊断只返回固定condition/phase，零build与业务/native写。原浏览器已成功登录后，URL提供的初始tenant仅留在页面内存，整页跳转到无query的applications时返回picker。Frontend负责 `main.tsx`、`tenant-selection.ts`与对应新回归测试三处窄修；Security仅继续remaining-only浏览器，不重新执行已成功的原登录、申请、审批或其他写步骤。

当前开发覆盖使用 `nginx:1.27-alpine`、UID101，只读挂载 `apps/portal-web/dist` 到 `/usr/share/nginx/html`，配置另外两处只读绑定。生产Dockerfile的 `kongos/portal-web:local`镜像留待最终生产验收，本轮不构建镜像。单独Portal workspace build即可刷新served静态文件；Vite closeBundle已有目录755/文件644规范，Nginx使用SPA try_files，无需reload/restart/recreate任何容器。`prepare-development.mjs`会执行全栈build，本轮禁止使用。

固定新标签 `portal-tenant-deep-link`，封存之前read-lock/failed-issue/immutable/nullable结果。新的helper只允许Portal构建产物变化，复用原12进程/C3三容器/退出bootstrap及migrator/当前私有env与scanner reference/监控generation/settings/catalog/epoch连续性，再额外核对API真实StartedAt与完整容器投影原样、API139及Console3产物字节原样、完整冻结源与所有公开应用/构建/部署源原样。

SQL仅经API runtime读取ConsoleDB，repeatable-read/read-only事务、10秒statement deadline/15秒调用上限，无KongDB或Admin请求。当前009证书已存在1行，首份grant已revoked generation2、旧failed grant已disabled；工具只核对fresh before/after值，绝不重复旧cert0/pending常量断言。两组原workflow全行/密文/账本/审计SQL-side SHA保留；同时数据库内聚合全部当前六grants、所有credentials、受管refs、证书与publication proofs的count与全行SHA（每组最多512）。整行配置/密文不出数据库。000–009全部checksum/applied_at一致，证书/proof runtime继续仅SELECT/INSERT。

只在新的tenant导出只读程序中，将grant查找绑定原发行workflow的不可变subject：origin.id为原WF参数、kind为portal-credential-issue、subject_type为portal_application_grants、subject_id为grant.id、CID/WID与grant严格相同。rotate/revoke已改变grant.workflow_id，不能使用该可变指针追溯原发行。原WF/Exec/version/steps/op/audit仍追原历史ID；历史FAILED_ISSUE/NULLABLE/PROOF工具及产品/迁移不修改。

Root源码冻结清单包括三处Portal修复及其测试、全Portal源码/Vite/tsconfig/package、root lockfile/manifests、Portal Dockerfile/Nginx和所有既有Compose overlays。Portal外产品、API/Console代码与全部SQL/migrator不变；新checker/tests/本方案属于明确授权的部署工具源，不改变产品行为。旧Root `source-proof-read-lock-repair-release-gate.json`作为产品差异基线；新Root gate固定为 `source-portal-tenant-deep-link-release-gate.json`，提供allPassed/sourceSha256/migrations。工具在所有Docker/private/SQL动作前校验新冻结SHA与旧产品差异只能落在tenant文件。

Root实际释放后只执行这四步，任一步失败保留证据并停止：

```sh
node deploy/scripts/verify-portal-tenant-static-continuity.mjs --before
npm run build -w @kongpilot/portal-web
node deploy/scripts/stage-deploy.mjs M6 --multicluster --observability --portal --verify-only
node deploy/scripts/verify-portal-tenant-static-continuity.mjs --after
```

普通Before先wx保留当前六类startup/boundary/Admin/metrics/Portal旧报告，再采集fresh连续性；既存档案仍拒绝普通Before。第二次失败已创建这六份档案、baseline未产生，本次必要续跑只能由新Root gate明确提供archivedBeforeResume：label、固定顺序六项archives（artifact/sha256/currentArtifact/currentSHA256）、failure（artifact/sha256）及diagnostic（artifact/sha256）。路径必须分别是该label的六previous报告、当前六原报告、coverage-corrected-deployment与snapshot-diagnostic。全部档案及原报告SHA须相同且匹配批准值；失败只能包含一次before退出1、所有写边界false，诊断须business-first/GRANT_UNAVAILABLE且buildfalse/native0/进程不变。baseline若已存在仍拒绝。续跑只读取既有档案，不重新copy/覆盖/删除；after封存规则不变。

After保存完整动态事实、API/Console固定SHA、Portal新index/JS/CSS SHA与结果。所有label完成结果（包括失败）均封存，不能覆写。Portal79检查同时证明实际8082 index/资产与当前dist逐字一致、UID可读、网络与CSP/API边界原样。startup15/boundary27/Admin37/metrics54/Portal79和真实连续性37项预计全部通过（合成测试仅1个保留服务时26项）。新报告与每条命令退出码/源码SHA单独归档；所有旧failure证据保留。既有verify-only包含expected-denied零行audit DELETE及被阻断的公开ingest POST边界探测，报告采用零业务/native写，不声称所有传递命令均为GET/SELECT。

禁止任何migration job、API/Console/global build、Portal镜像build、Docker up/restart/recreate、Nginx reload、env/network/material修改、capture/enroll/rotate、凭证reveal或业务/native写。门禁完成只交还Root；Root审阅后Security才验证tenant深链/整页刷新/无query导航/切换与无效slug拒绝，并在原remaining-only浏览器窗口继续授权的后续实际动作。
