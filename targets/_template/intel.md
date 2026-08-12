# 情报收集(Intel)

> 静态情报。WAF / 防爆破探针结果也写这里(进场探针后必填)。

## 基础信息

- **目标域名 / IP**:
- **所属公司 / SRC**:
- **备案信息 / Whois**:
- **接单日期**:
- **截止日期**:

## 探针结果(进场必填)

### 登录端点
- 弱口令试探:(密码错 vs 用户不存在区分?)
- 防爆破:(验证码 / IP 锁定 / 响应延迟?)
- 决策:(放手测 / 转入口)

### WAF
- 类型:(云 WAF / 硬件 WAF / 无 / 自研)
- 厂商:(阿里云 / Cloudflare / 安全狗 / ...)
- 拦截规则:(SQLi / XSS / 路径穿越,具体被拦了什么)
- 绕过姿势:(已知有效 / 待测试)

### 框架指纹
- 前端:(Vue / React / 原生)
- 后端:(Java / PHP / Node / Go / Python)
- Web 服务器:(Nginx / Tengine / Apache / Lighttpd)
- 中间件 / 监控:(Spring Actuator / Druid / Swagger / Eureka)
- 数据库特征:(MySQL / PG / Mongo / Mssql,有报错可推)

## 子域名与端口

(在此记录发现的子域名和开放端口)

## 敏感信息泄露

- GitHub 泄露:
- 网盘 / 文库泄露:
- JS 源码泄露:
- SourceMap 是否暴露:
- 内部域名 / IP:
- 硬编码密钥:

## 移动端 / 客户端

- 是否有 APP:(Android / iOS)
- 是否有小程序:(微信 / 支付宝 / 抖音)
- 是否有 PC 客户端 / 桌面端:
