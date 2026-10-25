# 构建报告

- 构建时间：2026-10-26 05:55:27（北京时间）
- 上游：[广告拦截&净化合集](https://github.com/fmz200/wool_scripts)（奶思 (fmz200)，GPL-3.0），上游日期 2026-10-25 22:36:13，内容摘要 `084197a83ab6`

| 段落 | 条目数 |
|---|---|
| Rule | 2814 |
| Header Rewrite | 0 |
| URL Rewrite | 512 |
| Body Rewrite | 85 |
| Map Local | 800 |
| Script | 188 |
| MITM | 873 |

## 被去除的条目

### 模块不应修改 [General]（1）

- `[General] force-http-engine-hosts = %APPEND% lzmh.lz-qs.com:5090`

### 由单独安装的 BiliBili: ADBlock（BiliUniverse）负责，避免重复处理（32）

- `[Header Rewrite] http-response ^https:\/\/grpc\.biliapi\.net\/bilibili\.app\.(interface\.v1\.(Teenagers\/ModeStatus|Search\/DefaultWords)|view\.v1\.View\/TFInfo|viewunite\.v1\.View\/ViewEndPage)$ head`
- `[URL Rewrite] ^https?:\/\/.+?\.kingsoft-office-service\.com - reject`
- `[URL Rewrite] ^https?:\/\/.*\/yyting\/advertclient\/ClientAdvertList.action - reject`
- `[URL Rewrite] ^https?:\/\/.+?\/music\/common\/upload\/t_splash_info\/ - reject`
- `[Body Rewrite] http-response-jq ^https:\/\/api\.bilibili\.com\/x\/pd-proxy\/tracker\? '.data[][]?="stun.chat.bilibili.com:3478"'`
- `[Body Rewrite] http-response-jq ^https:\/\/api\.bilibili\.com\/pgc\/view\/v2\/app\/season\? 'del(.data.payment)'`
- `[Body Rewrite] http-response-jq ^https:\/\/api\.bilibili\.com\/pgc\/page\/channel\? '.data.modules |= map(select(.type != "TIP") | if .type == "BANNER" then .module_data.items |= map(select(.url | sta`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/resource\/show\/skin\? 'delpaths([["data","common_equip"]])'`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/resource\/show\/tab\/v2\? '.data.tab = [     {         pos: 1,         id: 731,         name: "\u76F4\u64AD",         tab_id: "\u76F4\`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/v2\/splash\/(list|show|event\/list2)\? '.data |= with_entries(if .key | IN("show", "event_list") then .value = [] else . end)'`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/v2\/feed\/index\? 'if .data.items then .data.items |= map(select((.banner_item == null) and (.ad_info == null) and (.card_goto == "av"`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/v2\/feed\/index\/story\? 'if .data.items then .data.items |= map(select((.ad_info == null) and (.card_goto | IN("vertical_ad_av", "ver`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/v2\/account\/mine(\/ipad)?\? '.data |= (     del(.answer, .live_tip, .vip_section, .vip_section_v2, .modular_vip_section) |      .vip_`
- `[Body Rewrite] http-response-jq ^https:\/\/app\.bilibili\.com\/x\/v2\/account\/myinfo\? '.data.vip |= if . != null and .status == 0 then . + { status: 1, type: 2, due_date: 9005270400000, role: 15 } e`
- `[Map Local] ^https?:\/\/.+?\.58cdn\.com\.cn\/brandads\/ data-type=text data=" " status-code=200`
- `[Map Local] ^https:\/\/api\.live\.bilibili\.com\/xlive\/e-commerce-interface\/v1\/ecommerce-user\/get_shopping_info\? data-type=text data="{}" status-code=200 header="Content-Type:application/json"`
- `[Map Local] ^https:\/\/line3-h5-mobile-api\.biligame\.com\/game\/live\/large_card_material\? data-type=text data="{}" status-code=200 header="Content-Type:application/json"`
- `[Map Local] ^https:\/\/ap[ip]\.bilibili\.com\/x\/(resource\/(top\/activity|patch\/tab(\/v2)?)|v2\/search\/square|vip\/ads\/materials)\? data-type=text data="{"code":-404,"message":"-404","ttl":1,"data`
- `[Map Local] ^https:\/\/api\.bilibili\.com\/pgc\/activity\/deliver\/material\/receive\? data-type=text data="{"code":0,"data":{"closeType":"close_win","container":[],"showTime":""},"message":"success"}`
- `[Map Local] ^https:\/\/grpc\.biliapi\.net\/bilibili\.app\.interface\.v1\.Teenagers\/ModeStatus$ data-type=base64 data="AAAAABMKEQgCEgl0ZWVuYWdlcnMgAioA" header="Content-Type:text/plain"`
- `[Map Local] ^https:\/\/grpc\.biliapi\.net\/bilibili\.app\.interface\.v1\.Search\/DefaultWords$ data-type=base64 data="AAAAACEaHeaQnOe0ouinhumikeOAgeeVquWJp+aIlnVw5Li7KAE=" header="Content-Type:text/pl`
- `[Map Local] ^https:\/\/grpc\.biliapi\.net\/bilibili\.app\.(view\.v1\.View\/TFInfo|viewunite\.v1\.View\/ViewEndPage)$ data-type=base64 data="AAAAAAA=" header="Content-Type:text/plain"`
- `[Script] bilibili.airborne = type=http-request, pattern=^https:\/\/(grpc\.biliapi\.net|app\.bilibili\.com)\/bilibili\.community\.service\.dm\.v1\.DM\/DmSegMobile$, script-path=https://raw.githubuserco`
- `[Script] bilibili.request = type=http-request, pattern=^https:\/\/(grpc\.biliapi\.net|app\.bilibili\.com)\/bilibili\.(app\.viewunite\.v1\.View\/View|main\.community\.reply\.v1\.Reply\/MainList)$, scri`
- `[Script] bilibili.live = type=http-response, pattern=^https:\/\/api\.live\.bilibili\.com\/xlive\/(app-interface\/v2\/index\/feed|app-room\/v1\/index\/getInfoBy(Room|User))\?, script-path=https://raw.g`
- `[Script] bilibili.protobuf = type=http-response, pattern=^https:\/\/(grpc\.biliapi\.net|app\.bilibili\.com)\/bilibili\.(app\.(show\.v1\.Popular\/Index|dynamic\.v2\.Dynamic\/DynAll|view(unite)?\.v1\.Vi`
- `[Script] 香蕉是一种水果 = type=http-response, pattern=^https?:\/\/.+?\.(pipi|fuli|xiang(jiao|xiang))apps\.com\/(ucp\/index|getGlobalData|(\/|)vod\/reqplay\/), script-path=https://raw.githubusercontent.com/No`
- `[MITM] grpc.biliapi.net`
- `[MITM] app.bilibili.com`
- `[MITM] api.bilibili.com`
- `[MITM] api.live.bilibili.com`
- `[MITM] line3-h5-mobile-api.biligame.com`

### 付费接口改写，不收录（爱美剧）（4）

- `[URL Rewrite] ^https?:\/\/api\.bjxkhc\.com\/index\.php\/app\/ios\/ver/index_ios$ - reject`
- `[URL Rewrite] ^https?:\/\/api\.bjxkhc\.com\/index\.php\/app\/ios\/ads\/ - reject`
- `[Map Local] ^https?:\/\/api\.bjxkhc\.com\/index\.php\/app\/ios\/pay/ok$ data-type=text data="{}" status-code=200 header="Content-Type:application/json"`
- `[MITM] api.bjxkhc.com`

### 由单独安装的 WeChat增强（可莉）负责，避免重复处理（5）

- `[Body Rewrite] http-response ^https?:\/\/mp\.weixin\.qq\.com\/mp\/getappmsgad advertisement fmz200`
- `[Map Local] ^https?:\/\/mp\.weixin\.qq\.com\/mp\/cps_product_info\?action data-type=text data="{}" status-code=200 header="Content-Type:application/json"`
- `[MITM] mp.weixin.qq.com`
- `[MITM] weixin110.qq.com`
- `[MITM] security.wechat.com`

### 付费功能解锁，不收录（酷我音乐会员）（8）

- `[Map Local] ^https?:\/\/audiobookpay\.kuwo\.cn\/a\.p\?op=get_advertright_endtime data-type=text data="{}" status-code=200 header="Content-Type:application/json"`
- `[Script] 酷我音乐 = type=http-response, pattern=^https?:\/\/audiobookpay\.kuwo\.cn\/a\.p, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/kuwo/kuwo.js, requires-body=true, t`
- `[Script] 酷我音乐 = type=http-response, pattern=^https?:\/\/musicpay\.kuwo\.cn\/music\.pay, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/kuwo/kuwo.js, requires-body=true,`
- `[Script] 酷我音乐 = type=http-response, pattern=^https?:\/\/vip1\.kuwo\.cn\/vip\/(enc\/user\/vip\?op=ui|v\d\/theme\?op=gd), script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/k`
- `[Script] 酷我音乐 = type=http-response, pattern=^https?:\/\/vip1\.kuwo\.cn\/vip\/v\d\/user\/vip\?op=ui, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/kuwo/kuwo.js, require`
- `[MITM] audiobookpay.kuwo.cn`
- `[MITM] musicpay.kuwo.cn`
- `[MITM] vip1.kuwo.cn`

### 付费功能解锁，不收录（25）

- `[Script] 酷我音乐 = type=http-response, pattern=^https?:\/\/(mgxhtj|nmobi|searchrecterm)\.kuwo\.cn\/(mgxh|mobi|recterm)\.s, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/k`
- `[Script] 美丽修行广告 = type=http-response, pattern=^https:\/\/api\.bevol\.com\/(?:appmain\/app\/home\/page|usercenter\/account\/info|personal\/page|appmain\/app\/home\/launch|trialbox\/shop\/app\/homePage)`
- `[Script] 51job = type=http-response, pattern=^https?:\/\/cupid\.51job(app)?\.com\/open\/noauth\/recommend\/job-tab-dynamic, script-path=https://raw.githubusercontent.com/zirawell/R-Store/main/Res/Scri`
- `[Script] 去哒 = type=http-response, pattern=^https?:\/\/cupid\.51job(app)?\.com\/open\/my-page\/, script-path=https://raw.githubusercontent.com/zirawell/R-Store/main/Res/Scripts/AntiAd/51job.js, require`
- `[Script] NetEaseCloudMusic_mian = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/(batch|v\d\/resource\/comment\/floor\/get), script-path=https://raw.githubusercon`
- `[Script] NetEaseCloudMusic_tab = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/home\/framework\/tab, script-path=https://raw.githubusercontent.com/Keywos/r`
- `[Script] NetEaseCloudMusic_home = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/(homepage\/block\/page|link\/page\/rcmd\/(resource\/show|block\/resource\/multi\/`
- `[Script] NetEaseCloudMusic_fx = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/page\/discovery\/resource\/show, script-path=https://raw.githubusercontent.co`
- `[Script] NetEaseCloudMusic_mybarad = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/position\/show\/resource, script-path=https://raw.githubusercontent.com/`
- `[Script] NetEaseCloudMusic_foll = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/user\/follow\/users\/mixed\/get, script-path=https://raw.githubusercontent.com/Ke`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/\w{3}\/level\/info, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, requires-body`
- `[Script] rrtv_json = type=http-response, pattern=https://api.rr.tv/v3plus/index/channel\?pageNum=1&position=CHANNEL_INDEX, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Script`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/app\/config\/h5NativeBar, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, require`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/v3plus\/index\/channel\?pageNum=1&position=CHANNEL_MY, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/user\/privilege\/list, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, requires-b`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/ad\/getAll, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, requires-body=true, t`
- `[Script] rrtv_json = type=http-response, pattern=^https?:\/\/api\.rr\.tv\/drama\/app\/get_combined_drama_detail, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_jso`
- `[Script] rrtv_json = type=http-response, pattern=https://api.rr.tv/watch/v4, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, requires-body=true, timeout=60`
- `[Script] rrtv_json = type=http-response, pattern=https://api.rr.tv/user/profile, script-path=https://raw.githubusercontent.com/fmz200/wool_scripts/main/Scripts/rrtv_json.js, requires-body=true, timeou`
- `[Script] NetEaseCloudMusic_mian = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/(batch|v\d\/resource\/comment\/floor\/get), script-path=https://raw.githubusercon`
- `[Script] NetEaseCloudMusic_tab = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/home\/framework\/tab, script-path=https://raw.githubusercontent.com/Keywos/r`
- `[Script] NetEaseCloudMusic_home = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/(homepage\/block\/page|link\/page\/rcmd\/(resource\/show|block\/resource\/multi\/`
- `[Script] NetEaseCloudMusic_fx = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/page\/discovery\/resource\/show, script-path=https://raw.githubusercontent.co`
- `[Script] NetEaseCloudMusic_mybarad = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/link\/position\/show\/resource, script-path=https://raw.githubusercontent.com/`
- `[Script] NetEaseCloudMusic_foll = type=http-response, pattern=^https?:\/\/(ipv4|interface\d?)\.music\.163\.com\/e?api\/user\/follow\/users\/mixed\/get, script-path=https://raw.githubusercontent.com/Ke`

### 文件名显示为付费解锁/破解（1）

- `[Script] Protobuf = type=http-response, pattern=^https:\/\/(?:\w+-spclient|spclient\.wg)\.spotify\.com(?::443)?\/(?:bootstrap|user-customization-service), script-path=https://raw.githubusercontent.com`

### 上游脚本地址已失效（1）

- `[Script] UnblockURLinWeChat-解除微信链接限制 = type=http-response, pattern=^https\:\/\/(weixin110\.qq|security.wechat)\.com\/cgi-bin\/mmspamsupport-bin\/newredirectconfirmcgi\?, script-path=https://raw.github`

### 在解密保护范围内（*.gov.cn）（6）

- `[MITM] gab.122.gov.cn`
- `[MITM] fuwu.nhsa.gov.cn`
- `[MITM] szdmobile.suzhou.gov.cn`
- `[MITM] tfsmy.chengdu.gov.cn`
- `[MITM] portal.zjzwfw.gov.cn`
- `[MITM] app-izz.zhengzhou.gov.cn`

### 在解密保护范围内（*.ecitic.com）（3）

- `[MITM] ump.sz.creditcard.ecitic.com`
- `[MITM] m.creditcard.ecitic.com`
- `[MITM] wap.bank.ecitic.com`

### 在解密保护范围内（*.cebbank.com）（2）

- `[MITM] mobile.cebbank.com`
- `[MITM] yghsh.cebbank.com`

### 在解密保护范围内（*.icbc.com.cn）（3）

- `[MITM] v.icbc.com.cn`
- `[MITM] pv.elife.icbc.com.cn`
- `[MITM] elife.icbc.com.cn`

### 在解密保护范围内（*.hxb.com.cn）（1）

- `[MITM] static.creditcard.hxb.com.cn`

### 在解密保护范围内（*.ccb.com）（1）

- `[MITM] yunbusiness.ccb.com`

### 在解密保护范围内（*.cmbc.com.cn）（2）

- `[MITM] www.cmbc.com.cn`
- `[MITM] rs.creditcard.cmbc.com.cn`

### 在解密保护范围内（*.bankcomm.com）（2）

- `[MITM] creditcardapp.bankcomm.com`
- `[MITM] creditcard.bankcomm.com`

### 在解密保护范围内（*.abchina.com.cn）（1）

- `[MITM] midc.cdn-static.abchina.com.cn`

### 在解密保护范围内（*.abchina.com）（1）

- `[MITM] enjoy.cdn-static.abchina.com`

### 在解密保护范围内（*.pingan.com.cn）（2）

- `[MITM] iobs.pingan.com.cn`
- `[MITM] hcz-member.pingan.com.cn`

### 在解密保护范围内（*.pingan.com）（1）

- `[MITM] pacdn.m.stock.pingan.com`

### 在解密保护范围内（*.spdb.com.cn）（2）

- `[MITM] lban.spdb.com.cn`
- `[MITM] wap.spdb.com.cn`

### 无效的主机名（2）

- `[MITM] cupid.51job*.comhostname`
- `[MITM] res1.hubcloud.com.cnhostname`

### 付费功能解锁，不收录（Spotify）（2）

- `[MITM] *-spclient.spotify.com`
- `[MITM] spclient.wg.spotify.com`

### 在解密保护范围内（*.tenpay.com）（1）

- `[MITM] ccmsupport-sz.tenpay.com`

### 在解密保护范围内（*.189.cn）（2）

- `[MITM] api.cloud.189.cn`
- `[MITM] cloud.189.cn`

### 在解密保护范围内（*.psbc.com）（4）

- `[MITM] static.psbc.com`
- `[MITM] mcc.psbc.com`
- `[MITM] static.mobile-bank.psbc.com`
- `[MITM] d.psbc.com`

### 在解密保护范围内（*.googlevideo.com）（1）

- `[MITM] rr*.googlevideo.com`

### 在解密保护范围内（*.googleapis.com）（1）

- `[MITM] youtubei.googleapis.com`

### 在解密保护范围内（*.boc.cn）（2）

- `[MITM] openapi.boc.cn`
- `[MITM] mlife.jf365.boc.cn`

### 在解密保护范围内（*.citicbank.com）（1）

- `[MITM] imcs.citicbank.com`

### 在解密保护范围内（*.cmbchina.com）（6）

- `[MITM] webappcfg.paas.cmbchina.com`
- `[MITM] mbmodule-openapi.paas.cmbchina.com`
- `[MITM] mbasecc.bas.cmbchina.com`
- `[MITM] mbasecc.bcs.cmbchina.com`
- `[MITM] intellicc.bas.cmbchina.com`
- `[MITM] intellicc.bcs.cmbchina.com`

### 在解密保护范围内（*.10086.cn）（3）

- `[MITM] client.app.coc.10086.cn`
- `[MITM] app.10086.cn`
- `[MITM] mcmm.caiyun.feixin.10086.cn`

### 在解密保护范围内（*.10010.com）（2）

- `[MITM] m.client.10010.com`
- `[MITM] m1.ad.10010.com`
