# SAML 认证服务示例 (Kotlin)

本项目是一个基于 Spring Boot 3.4 和 Spring Security 实现的 SAML Identity Provider (IdP) 示例。

## 核心功能
- 作为 SAML Identity Provider (IdP) 运行。
- 提供动态生成的 IdP 元数据。
- 支持 SAML 2.0 Web SSO 配置文件（HTTP-Redirect 和 HTTP-POST 绑定）。
- 内置简单的基于表单的身份验证（用户名：`user`，密码：`password`）。
- 使用自签名证书进行响应签名。

## 如何运行
1. 确保已安装 JDK 21。
2. 在根目录下运行：
   ```bash
   ./gradlew bootRun
   ```

## 如何测试
1. 访问 `http://localhost:8080/`。
2. 系统会提示登录，使用用户名 `user` 和密码 `password`。
3. 登录后，你将看到欢迎页面。
4. 访问 `http://localhost:8080/saml2/idp/metadata` 获取 IdP 元数据，供 Service Provider (SP) 使用。

## 关键端点
- **IdP Metadata URL**: `http://localhost:8080/saml2/idp/metadata`
- **SSO Service URL (Redirect/POST)**: `http://localhost:8080/saml2/idp/sso`
- **Entity ID**: `http://localhost:8080/saml2/idp/metadata`

## 证书信息
证书和私钥位于 `src/main/resources/credentials` 目录下。在配置 SP 时，你需要将 `rp-certificate.crt` 的内容提供给 SP，或者直接使用上述元数据 URL。
