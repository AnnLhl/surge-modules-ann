# surge-modules-ann

个人用的 Surge iOS 去广告模块，每天自动从上游构建一次。

## 安装

Surge → 模块 → 安装新模块，填入：

```
https://raw.githubusercontent.com/AnnLhl/surge-modules-ann/main/dist/Anning-AdBlock.sgmodule
```

需要 MITM 证书已安装并信任。

## 内容

上游是奶思（[fmz200/wool_scripts](https://github.com/fmz200/wool_scripts)）的「广告拦截&净化合集」，覆盖约 730 款 App 和小程序，GPL-3.0 许可。构建时做了这些修改（规则见 `config/`）：

| 修改 | 原因 |
|---|---|
| 去除付费功能解锁 | 只做去广告。按脚本地址清单、文件名，以及脚本内容特征（把会员标记改成真、把会员到期时间改到很远的将来）自动识别并去除 |
| 去除哔哩哔哩主 App 的重写 | 由单独安装的 BiliBili: ADBlock（BiliUniverse）负责，避免两套重写处理同一个请求 |
| 去除微信公众号与外链解锁部分 | 由单独安装的 WeChat增强（可莉）负责 |
| 不解密银行、支付、运营商、政务、Apple、Google API 和 AI 服务 | 保护登录、支付、验证码 |
| 在规则最前面加入例外放行（`config/exceptions.list`） | 避免误拦腾讯视频播放、友盟推送、个推地震速报、知乎消息等 |
| 只保留拦截类规则，去除重复项与无效主机名 | 模块里的规则先于主配置匹配，不能让上游规则改变主配置的分流 |

每次构建的明细（来源日期、各段数量、去除了哪些条目、脚本增减）见 [`dist/REPORT.md`](dist/REPORT.md)。

## 推荐的模块组合（排序页从上到下）

1. HTTPDNS拦截器（可莉）
2. **Anning 去广告**（本仓库）
3. BiliBili: ADBlock（BiliUniverse）
4. WeChat增强（可莉）
5. Anning 例外放行（本地模块，放最底部，优先级最高）

可莉的模块条款不允许二次修改和公开分发，所以不合并进来，直接从作者地址安装，作者更新后 Surge 会自动同步。

## 自动更新

- GitHub Actions 每天 03:23（北京时间）构建；修改 `config/` 或 `build/` 后也会立即构建。
- 上游获取失败或内容异常时，沿用上一次成功的版本，不会把模块清空；这次运行会标记为失败。
- 内容有变化才提交；每月 1 日写一次 `status/heartbeat.txt`，防止定时任务因仓库长期无活动被 GitHub 停用。
- Surge 按"外部资源"的更新间隔拉取新版本，也可以在模块页手动更新。

## 出现广告或误拦时

- 误拦：先在 Surge 最近请求里看命中的规则。临时放行写进手机上的"Anning 例外放行"本地模块；确认后再加到 `config/exceptions.list`（只能写国内域名 + `DIRECT`）。
- 某个 App 还有广告：记下 App 名称和出现位置，补充到 `config/`，或者从其他开源项目加来源（先核对许可证）。
- 临时停用：在 Surge 模块页关闭本模块即可。

## 文件

| 路径 | 作用 |
|---|---|
| `config/sources.json` | 上游地址 |
| `config/policy.json` | 去除清单、受保护的主机与解密范围 |
| `config/exceptions.list` | 例外放行规则 |
| `build/build.py` | 构建脚本（只用 Python 标准库） |
| `build/lint.py` | 构建后的静态检查 |
| `dist/` | 生成的模块与报告 |
| `cache/` | 上游与脚本检查结果的缓存，用于失败回退 |

## 许可

本仓库以 GPL-3.0 发布（见 `LICENSE`）。模块内容来自上游作者，各条目的原作者见模块内注释。
