# foxreq 单文件 FastAPI 服务设计

日期：2026-07-16

## 目标

提供一个单文件 FastAPI 服务，让受信任局域网中的客户端通过普通 HTTP 调用本机已安装的 foxreq，并由 foxreq 使用 Firefox 152 NSS 档案访问调用方指定的 HTTPS 目标。

该服务只面向临时、低并发、已授权测试。它不包含生产网关所需的身份认证、租户隔离、持久化、审计或公网防护。

## 交付物

- `examples/fastapi_service.py`：唯一的服务实现文件，可直接用项目 `.venv` 启动。
- `tests/python/test_fastapi_service.py`：输入契约和真实回环链路测试。
- `pyproject.toml`：增加 `service` 可选依赖，不改变 foxreq 的最小运行时依赖。
- `README.md`：增加中文启动、调用、安全边界和返回结构说明。

“单文件”指服务实现本身不拆分模块；自动化测试和文档仍保持独立文件。

## 运行方式

脚本通过 `if __name__ == "__main__"` 启动 uvicorn，默认参数为：

- host：`0.0.0.0`，允许局域网访问；
- port：`8000`；
- workers：固定为 1；
- access log：保留 HTTP 路径和状态码，但上游 URL 位于 JSON 请求体，不进入 access log；
- NSS runtime：从 `--runtime` 或 `FOXREQ_NSS_RUNTIME_DIR` 解析。

启动时输出明确警告：服务无鉴权，只能用于受信任局域网，不得映射公网端口。脚本不自动修改 Windows 防火墙；若系统弹出网络访问提示，由用户决定是否只允许专用网络。

## HTTP API

### `GET /health`

返回不含本机路径和敏感信息的状态：

```json
{
  "status": "ok",
  "foxreq_version": "0.1.0",
  "profile": "firefox_152",
  "max_concurrency": 1,
  "runtime_ready": true
}
```

### `POST /v1/request`

请求示例：

```json
{
  "method": "GET",
  "url": "https://example.test/path",
  "params": [["page", "1"]],
  "headers": [["Accept", "application/json"]],
  "timeout": 15.0
}
```

字段契约：

- `method`：只允许 `GET` 或 `POST`；
- `url`：只允许绝对 HTTPS URL，不允许 userinfo、fragment 或控制字符；
- `params`：可选的有序键值对列表；
- `headers`：可选的有序键值对列表，保留重复请求头；
- `data`：可选 UTF-8 文本正文；
- `json`：可选 JSON 值；
- `data` 与 `json` 互斥；
- `timeout`：默认 15 秒，范围为 0.1 到 30 秒。

调用方不能控制 `verify`、`runtime_dir` 或 `impersonate`。服务固定启用证书验证并使用 `firefox_152`，避免通过接口关闭 TLS 校验或加载任意本机文件。

成功时 FastAPI 自身返回 HTTP 200，上游状态放在 JSON 中：

```json
{
  "status_code": 200,
  "reason": "OK",
  "url": "https://example.test/path?page=1",
  "http_version": "HTTP/1.1",
  "headers": [["Content-Type", "application/json"]],
  "body_base64": "e30=",
  "body_length": 2
}
```

响应头使用有序键值对列表以保留重复字段；正文使用 Base64，保证二进制响应可无损传输。

## 数据流和生命周期

1. uvicorn 接收局域网 HTTP JSON 请求。
2. FastAPI/Pydantic 校验字段、数量、长度、URL 和超时。
3. 进程级非阻塞信号量只允许一个 foxreq 调用；繁忙时立即返回 503。
4. 同步 foxreq 调用在线程池中执行，避免阻塞 ASGI 事件循环。
5. 每个 API 调用创建一个短生命周期 foxreq Session，请求结束即关闭。
6. 响应被转换为有限大小的 JSON envelope。

不复用全局 Session 的原因是服务允许任意 HTTPS 源站；全局 Session 会为不断变化的源站保留空闲连接，增加无界资源占用和并发生命周期复杂度。临时测试服务优先选择可预测资源释放。

## 限制和安全边界

- 服务无身份认证，任何能访问监听端口的局域网客户端都能调用；
- 不得配置路由器端口映射、反向代理公网入口或云安全组公网放行；
- 上游只允许 HTTPS，`http://`、`file://` 和其他 scheme 由服务和 foxreq 双重拒绝；
- 允许调用方指定任意 HTTPS 主机，包括局域网主机，因此该接口具有 SSRF/代理能力，只能在受信任网络临时运行；
- 仅允许一个在途请求；不提供压测或多 worker 模式；
- 请求 headers/params 各最多 64 对，单个名称和值限制长度；
- `data` 或 JSON 序列化后的正文最多 1 MiB；
- 返回正文最多 2 MiB，超出时返回 502，不把正文写入日志；
- 不记录上游请求头、Cookie、Authorization 值、请求正文或响应正文；
- 不支持重定向、Cookie jar、代理、HTTP/2 或流式响应。

这是刻意受限的测试工具，不是通用正向代理。

## 错误映射

- 400：服务级 URL、正文互斥或输入限制错误；
- 422：FastAPI/Pydantic 字段类型错误；
- 502：foxreq 连接、TLS、证书、协议错误，或上游响应超过服务限制；
- 503：已有一个 foxreq 请求在执行；
- 504：foxreq 超时；
- 500：未分类内部错误，只返回通用消息，不包含请求头、正文或本机路径。

错误响应只返回稳定的 `error` 类型和安全消息。服务端日志记录错误类别，不记录调用参数内容。

## 依赖

`pyproject.toml` 增加独立的 `service` extra，包含 FastAPI 和 uvicorn。普通 foxreq wheel 的默认依赖仍只有 certifi；未选择 `service` extra 的用户不会安装 Web 服务依赖。

依赖只安装到 `D:\code\逆向\foxreq\.venv`，不修改系统 Python、用户 PATH 或全局 site-packages。

## 测试

测试保持串行并仅使用回环地址：

1. 导入和 `/health` 契约；
2. HTTP 上游 URL、userinfo、fragment、超时和正文冲突拒绝；
3. 并发信号量繁忙时返回 503；
4. foxreq 异常到 400/502/504 的稳定映射；
5. FastAPI 回环 HTTP → foxreq → 本地 HTTPS fixture → NSS 的真实 GET；
6. JSON POST、重复请求头和 Base64 响应；
7. 服务日志和响应中不出现测试用 Authorization/Cookie/正文标记；
8. 完整 Python 套件、pip check、差异检查和敏感标记扫描。

测试不会访问第三方站点，也不会启动多 worker 或执行压力测试。

## 非目标

- 本阶段不增加鉴权、客户端 IP allowlist 或 TLS 入站终止；
- 不实现 Linux 服务部署；
- 不扩展 foxreq 的 HTTP 上游支持；
- 不增加新的 Firefox TLS 档案；
- 不实现后台守护、自启动、Windows 服务或防火墙自动配置。
