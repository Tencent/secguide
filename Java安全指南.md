<details markdown="1">
  <summary>目录</summary>

-   [1 安卓类](#1)
    *   [I. 代码实现](#1.1)
		+   [1.1 异常捕获处理](#1.1.1)
		+   [1.2 数据泄露](#1.1.2)
		+   [1.3 webview 组件安全](#1.1.3)
		+   [1.4 传输安全](#1.1.4)
    *   [II. 配置&环境](#1.2)
		+   [2.1 AndroidManifest.xml 配置](#1.2.1)
-   [2 后台类](#2)
    *   [I. 代码实现](#2.1)
		+   [1.1 数据持久化](#2.1.1)
		+   [1.2 文件操作](#2.1.2)
		+   [1.3 文件操作](#2.1.3)
		+   [1.4 XML读写](#2.1.4)
		+   [1.5 响应输出](#2.1.5)
		+   [1.6 OS命令执行](#2.1.6)
		+   [1.7 会话管理](#2.1.7)
		+   [1.8 加解密](#2.1.8)
		+   [1.9 查询业务](#2.1.9)
		+   [1.10 操作业务](#2.1.10)
</details>

<a id="1"></a>
## 安卓类
<a id="1.1"></a>
### I. 代码实现
<a id="1.1.1"></a>
#### 1.1 异常捕获处理
##### 1.1.1 【必须】序列化异常捕获
对于通过导出组件 intent 传递的序列化对象，必须进行 try...catch 处理，以避免数据非法导致应用崩溃。 
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        try {
            Intent mIntent = getIntent(); 
            //String msg = intent.getStringExtra("data"); 
            Person mPerson = (Person)mIntent.getSerializableExtra(ObjectDemo.SER_KEY)
            //textView.setText(msg); 
        } catch (ClassNotFoundException exp) {
            // ......
        }
    }
}
```
##### 1.1.2 【必须】NullPointerException 异常捕获
对于通过 intent getAction 方法获取数据时，必须进行 try...catch 处理，以避免空指针异常导致应用崩溃。
```java
public class MainActivity extends Activity {
    
    protected void onCreate(Bundle savedInstanceState) {
        try {
            Intent mIntent = getIntent(); 
            if mIntent.getAction().equals("StartNewWorld") {
                // ......
            }
            // ......
        } catch (NullPointerException exp) {
            // ......
        }
    }
}
```
##### 1.1.3 【必须】ClassCastException 异常捕获
对于通过 intent getSerializableExtra 方法获取数据时，必须进行 try...catch 处理，以避免类型转换异常导致应用崩溃。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        try {
            Intent mIntent = getIntent(); 
            Person mPerson = (Person)mIntent.getSerializableExtra(ObjectDemo.SER_KEY)
            // ......
        } catch (ClassCastException exp) {
            // ......
        }
    }
}
```
##### 1.1.4 【必须】ClassNotFoundException 异常捕获
同 1.1.3

<a id="1.1.2"></a>
#### 1.2 数据泄露
##### 1.2.1 【必须】logcat 输出限制
release 版本禁止在 logcat 输出信息。
```java
public class MainActivity extends Activity {
    String DEBUG = "debug_version";

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        if (DEBUG == "debug_version") {
            Log.d("writelog", "start activity");
        }
        // ......
    }
}
```

<a id="1.1.3"></a>
#### 1.3 webview 组件安全
##### 1.3.1 【必须】addJavaScriptInterface 方法调用
对于设置 minsdk <= 18 的应用，禁止调用 addJavaScriptInterface 方法。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        mWebView = new WebView(this);
        if (Build.VERSION.SDK_INT > 18) {
            mWebView.addJavascriptInterface(new wPayActivity.InJavaScriptLocalObj(this), "local_obj");
        }
        // ......
    }
}
```
##### 1.3.2 【建议】setJavaScriptEnabled 方法调用
如非必要，setJavaScriptEnabled 应设置为 false 。加载本地 html ，应校验 html 页面完整性，以避免 xss 攻击。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        mWebView = new WebView(this);
        mWebView.getSettings().setJavaScriptEnabled(false);
        // ......
    }
}
```
##### 1.3.3 【建议】setAllowFileAccess 方法调用
建议禁止使用 File 域协议，以避免过滤不当导致敏感信息泄露。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        mWebView = new WebView(this);
        mWebView.getSettings().setAllowFileAccess(false);
        // ......
    }
}
```
##### 1.3.4 【建议】setSavePassword 方法调用
建议 setSavePassword 的设置为 false ，避免明文保存网站密码。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        mWebView = new WebView(this);
        mWebView.getSettings().setSavePassword(false);
        // ......
    }
}
```
##### 1.3.5 【必须】onReceivedSslError 方法调用
webview 组件加载网页发生证书认证错误时，不能直接调用 handler.proceed() 忽略错误，应当处理当前场景是否符合业务预期，以避免中间人攻击劫持。
```java
public class MainActivity extends Activity {

    protected void onCreate(Bundle savedInstanceState) {
        // ......
        mWebView = new WebView(this);
        mWebView.setWebViewClient(new WebViewClient() {
            @Override
            public void onReceivedSslError(WebView view, SslErrorHandler handler, SslError error) {
                // must check error 
                check_error();
                handler.proceed();
            }
        }
        // ......
    }
}
```
<a id="1.1.4"></a>
#### 1.4 传输安全
##### 1.4.1 【必须】自定义 HostnameVerifier 类
自定义 HostnameVerifier 类后，必须实现 verify 方法校验域名，以避免中间人攻击劫持。
```java
public class MainActivity extends Activity {
    
    protected void onCreate(Bundle savedInstanceState) {
        // ......
        HostnameVerifier hnv = new HostnameVerifier() {
            @Override
            public boolean verify(String hostname, SSLSession session) {
                // must to do
                isValid = checkHostName(hostname);
                return isValid;
            }
        };
        // ......
    }
}
```
##### 1.4.2 【必须】自定义 X509TrustManager 类
自定义 X509TrustManager 类后，必须实现 checkServerTrusted 方法校验服务器证书，以避免中间人攻击劫持。
```java
public class MainActivity extends Activity {
    
    protected void onCreate(Bundle savedInstanceState) {
        // ......
        TrustManager tm = new X509TrustManager() {
            public void checkServerTrusted(X509Certificate[] chain, String authType)
                    throws CertificateException {
                // must to do
                check_server_valid();
            }
        };
        // ......
    }
}
```
##### 1.4.3 【必须】setHostnameVerifier 方法调用
禁止调用 setHostnameVerifier 方法设置 ALLOW_ALL_HOSTNAME_VERIFIER 属性，以避免中间人攻击劫持。
```java
public class MainActivity extends Activity {
    
    protected void onCreate(Bundle savedInstanceState) {
        // ......
        SchemeRegistry schemeregistry = new SchemeRegistry();
        SSLSocketFactory sslsocketfactory = SSLSocketFactory.getSocketFactory();
        // set STRICT_HOSTNAME_VERIFIER
        sslsocketfactory.setHostnameVerifier(SSLSocketFactory.STRICT_HOSTNAME_VERIFIER);
        // ......
    }
}
```

<a id="1.2"></a>
### II. 配置&环境 
<a id="1.2.1"></a>
#### 2.1 AndroidManifest.xml 配置
##### 2.1.1 【必须】PermissionGroup 属性设置
禁止设置 PermissionGroup 属性为空。
##### 2.1.2 【必须】protectionLevel 属性设置
对于自定义权限的 protectionLevel 属性设置，建议设置为 signature 或 signatureOrSystem。
##### 2.1.3 【建议】sharedUserId 权限设置
最小范围和最小权限使用 sharedUserId 设置。
##### 2.1.4 【建议】allowBackup 备份设置
如非产品功能需要，建议设置 allowBackup 为 false。
```java
<application android:allowBackup="false"> 
</application>
```
##### 2.1.5 【必须】debuggable 调试设置
release 版本禁止设置 debuggable 为 true。
```java
<application android:debuggable="false"> 
</application>
```


<a id="2"></a>
## 后台类
<a id="2.1"></a>
### I. 代码实现
<a id="2.1.1"></a>
#### 1.1 数据持久化

##### 1.1.1【必须】SQL语句默认使用预编译并绑定变量

Web后台系统应默认使用预编译绑定变量的形式创建sql语句，保持查询语句和数据相分离。以从本质上避免SQL注入风险。

如使用Mybatis作为持久层框架，应通过\#{}语法进行参数绑定，MyBatis 会创建 `PreparedStatement` 参数占位符，并通过占位符安全地设置参数。

示例：JDBC

```java
String custname = request.getParameter("name"); 
String query = "SELECT * FROM user_data WHERE user_name = ? ";
PreparedStatement pstmt = connection.prepareStatement( query );
pstmt.setString( 1, custname); 
ResultSet results = pstmt.executeQuery( );
```

Mybatis

```java
<select id="queryRuleIdByApplicationId" parameterType="java.lang.String" resultType="java.lang.String">    
      select rule_id from scan_rule_sqlmap_tab where application_id=#{applicationId} 
</select>

```

应避免外部输入未经过滤直接拼接到SQL语句中，或者通过Mybatis中的${}传入SQL语句（即使使用PreparedStatement，SQL语句直接拼接外部输入也同样有风险。例如Mybatis中部分参数通过${}传入SQL语句后实际执行时调用的是PreparedStatement.execute()，同样存在注入风险）。

##### 1.1.2【必须】白名单过滤

对于表名、列名等无法进行预编译的场景，比如外部数据拼接到order by, group by语句中，需通过白名单的形式对数据进行校验，例如判断传入列名是否存在、升降序仅允许输入“ASC”和“DESC”、表名列名仅允许输入字符、数字、下划线等。参考示例：

```java
public String someMethod(boolean sortOrder) {
 String SQLquery = "some SQL ... order by Salary " + (sortOrder ? "ASC" : "DESC");`
 ...
```

<a id="2.1.2"></a>
#### 1.2 文件操作

##### 1.2.1【必须】文件类型限制

须在服务器端采用白名单方式对上传或下载的文件类型、大小进行严格的限制。仅允许业务所需文件类型上传，避免上传.jsp、.jspx、.class、.java等可执行文件。参考示例：

```java
       String file_name = file.getOriginalFilename();
        String[] parts = file_name.split("\\.");
        String suffix = parts[parts.length - 1];
        switch (suffix){
            case "jpeg":
                suffix = ".jpeg";
                break;
            case "jpg":
                suffix = ".jpg";
                break;
            case "bmp":
                suffix = ".bmp";
                break;
            case "png":
                suffix = ".png";
                break;
            default:
                //handle error
                return "error";
        }
```

##### 1.2.2【必须】禁止外部文件存储于可执行目录

禁止外部文件存储于WEB容器的可执行目录（appBase）。建议保存在专门的文件服务器中。

##### 1.2.3【建议】避免路径拼接

文件目录避免外部参数拼接。保存文件目录建议后台写死并对文件名进行校验（字符类型、长度）。建议文件保存时，将文件名替换为随机字符串。

##### 1.2.4【必须】避免路径穿越

如因业务需要不能满足1.2.3的要求，文件路径、文件命中拼接了不可行数据，需判断请求文件名和文件路径参数中是否存在../或..\\(仅windows)， 如存在应判定路径非法并拒绝请求。		

<a id="2.1.3"></a>
#### 1.3 网络访问

##### 1.3.1【必须】避免直接访问不可信地址

服务器访问不可信地址时，禁止访问私有地址段及内网域名。
```
// 以RFC定义的专有网络为例，如有自定义私有网段亦应加入禁止访问列表。
10.0.0.0/8
172.16.0.0/12
192.168.0.0/16
127.0.0.0/8
```

建议通过URL解析函数进行解析，获取host或者domain后通过DNS获取其IP，然后和内网地址进行比较。

对已校验通过地址进行访问时，应关闭跟进跳转功能。

参考示例：

```java
     httpConnection = (HttpURLConnection) Url.openConnection();

     httpConnection.setFollowRedirects(false);
```

<a id="2.1.4"></a>
#### 1.4 XML读写

##### 1.4.1【必须】XML解析器关闭DTD解析

读取外部传入XML文件时，XML解析器初始化过程中设置关闭DTD解析。

参考示例：

javax.xml.parsers.DocumentBuilderFactory

```java
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
try {
    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
    dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
    dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
    dbf.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
    dbf.setXIncludeAware(false);
    dbf.setExpandEntityReferences(false);
    ……
}
```

org.dom4j.io.SAXReader

```java
saxReader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
saxReader.setFeature("http://xml.org/sax/features/external-general-entities", false);
saxReader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```

org.jdom2.input.SAXBuilder

```java
SAXBuilder builder = new SAXBuilder();
builder.setFeature("http://apache.org/xml/features/disallow-doctype-decl",true);
builder.setFeature("http://xml.org/sax/features/external-general-entities", false);
builder.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
Document doc = builder.build(new File(fileName));
```

org.xml.sax.XMLReader

```java
XMLReader reader = XMLReaderFactory.createXMLReader();
reader.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
reader.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
reader.setFeature("http://xml.org/sax/features/external-general-entities", false);
reader.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
```


<a id="2.1.5"></a>
#### 1.5 响应输出

##### 1.5.1【必须】设置正确的HTTP响应包类型

响应包的HTTP头“Content-Type”必须正确配置响应包的类型，禁止非HTML类型的响应包设置为“text/html”。此举会使浏览器在直接访问链接时，将非HTML格式的返回报文当做HTML解析，增加反射型XSS的触发几率。

##### 1.5.2【建议】设置安全的HTTP响应头

- X-Content-Type-Options：

​        建议添加“X-Content-Type-Options”响应头并将其值设置为“nosniff”，可避免部分浏览器根据其“Content-Sniff”特性，将一些非“text/html”类型的响应作为HTML解析，增加反射型XSS的触发几率。

- HttpOnly：

​         控制用户登录鉴权的Cookie字段 应当设置HttpOnly属性以防止被XSS漏洞/JavaScript操纵泄漏。

- X-Frame-Options：

​        设置X-Frame-Options响应头，并根据需求合理设置其允许范围。该头用于指示浏览器禁止当前页面在frame、iframe、embed等标签中展现。从而避免点击劫持问题。它有三个可选的值：
​        DENY： 浏览器会拒绝当前页面加载任何frame页面；
​		SAMEORIGIN：则frame页面的地址只能为同源域名下的页面
​		ALLOW-FROM origin：可以定义允许frame加载的页面地址。

- Access-Control-Allow-Origin

  当需要配置CORS跨域时，应对请求头的Origin值做严格过滤。

  ```java
  ...
  String currentOrigin = request.getHeader("Origin");
  if (currentOrigin.equals("https://domain.qq.com")) {
         response.setHeader("Access-Control-Allow-Origin", currentOrigin);
             }
   ...
  ```

  

##### 1.5.3【必须】外部输入拼接到response页面前进行编码处理

当响应“content-type”为“html”类型时，外部输入拼接到响应包中，需根据输出位置进行编码处理。编码规则：

| 场景                                                         | 编码规则                                                     |
| ------------------------------------------------------------ | ------------------------------------------------------------ |
| 输出点在HTML标签之间                                         | 需要对以下6个特殊字符进行HTML实体编码(&, <, >, ", ',/)。<br/>示例：<br/>& --> &amp;amp;<br/>< --> &amp;lt;<br/>>--> &amp;gt;<br/>" --> &amp;quot;<br/>' --> &amp;#x27;  <br/>/ --> &amp;#x2F; |
| 输出点在HTML标签普通属性内（如href、src、style等，on事件除外） | 要对数据进行HTML属性编码。<br/>编码规则：除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为&#xHH;(以&#x开头，HH则是指该字符对应的十六进制数字，分号作为结束符) |
| 输出点在JS内的数据中                                         | 需要进行js编码<br/>编码规则：<br/>除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 \xHH （以 \x 开头，HH则是指该字符对应的十六进制数字）<br/>Tips：这种场景仅限于外部数据拼接在js里被引号括起来的变量值中。除此之外禁止直接将代码拼接在js代码中。 |
| 输出点在CSS中（Style属性）                                   | 需要进行CSS编码<br/>编码规则：<br/>除了阿拉伯数字和字母，对其他所有的字符进行编码，只要该字符的ASCII码小于256。编码后输出的格式为 \HH （以 \ 开头，HH则是指该字符对应的十六进制数字） |
| 输出点在URL属性中                                            | 对这些数据进行URL编码<br/>Tips：除此之外，所有链接类属性应该校验其协议。禁止JavaScript、data和Vb伪协议。 |


以上编码规则相对较为繁琐，可参考或直接使用业界已有成熟第三方库如ESAPI.其提供以下函数对象上表中的编码规则:

```java
ESAPI.encoder().encodeForHTML();
ESAPI.encoder().encodeForHTMLAttribute();
ESAPI.encoder().encodeForJavaScript();
ESAPI.encoder().encodeForCSS();
ESAPI.encoder().encodeForURL();
```

##### 1.5.4【必须】外部输入拼接到HTTP响应头中需进行过滤

应尽量避免外部可控参数拼接到HTTP响应头中，如业务需要则需要过滤掉“\r”、"\n"等换行符，或者拒绝携带换行符号的外部输入。

##### 1.5.5【必须】避免不可信域名的302跳转

如果对外部传入域名进行302跳转，必须设置可信域名列表并对传入域名进行校验。

为避免校验被绕过，应避免直接对URL进行字符串匹配。应通过通过URL解析函数进行解析，获取host或者domain后和白名单进行比较。

需要注意的是，由于浏览器的容错机制，域名`https://www.qq.com\www.bbb.com`中的`\`会被替换成`/`，最终跳转到`www.qq.com`。而Java的域名解析函数则无此特性。为避免解析不一致导致绕过，建议对host中的`/`和`#`进行替换。

参考代码：

```java
String host="";
		try {
		    url = url.replaceAll("[\\\\#]","/"); //替换掉反斜线和井号
		    host = new URL(url).getHost();  
		} catch (MalformedURLException e) {
		    e.printStackTrace();
		}
		if (host.endsWith(".qq.com")){
			//跳转操作
		}else{
			return;
		}
```



##### 1.5.6【必须】避免通过Jsonp传输非公开敏感信息

jsonp请求再被CSRF攻击时，其响应包可被攻击方劫持导致信息泄露。应避免通过jsonp传输非公开的敏感信息，例如用户隐私信息、身份凭证等。

##### 1.5.7【必须】限定JSONP接口的callback字符集范围

JSONP接口的callback函数名为固定白名单。如callback函数名可用户自定义，应限制函数名仅包含 字母、数字和下划线。如：`[a-zA-Z0-9_-]+`

#####  1.5.8【必须】屏蔽异常栈

应用程序出现异常时，禁止将数据库版本、数据库结构、操作系统版本、堆栈跟踪、文件名和路径信息、SQL 查询字符串等对攻击者有用的信息返回给客户端。建议重定向到一个统一、默认的错误提示页面，进行信息过滤。

##### 1.5.9【必须】模板&表达式

web view层通常通过模板技术或者表达式引擎来实现界面与业务数据分离，比如jsp中的EL表达式。这些引擎通常可执行敏感操作，如果外部不可信数据未经过滤拼接到表达式中进行解析。则可能造成严重漏洞。

下列是基于EL表达式注入漏洞的演示demo： 		

```java
	@RequestMapping("/ELdemo")
	@ResponseBody
	public String ELdemo(RepeatDTO repeat) {
		ExpressionFactory expressionFactory = new ExpressionFactoryImpl();
        SimpleContext simpleContext = new SimpleContext();
        String exp = "${"+repeat.getel()+"}";
        ValueExpression valueExpression =       expressionFactory.createValueExpression(simpleContext, exp, String.class);		
		return valueExpression.getValue(simpleContext).toString();
	}
```

外部可通过el参数，将不可信输入拼接到EL表达式中并解析。

此时外部访问：x.x.x.x/ELdemo?el=”''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'open /Applications/Calculator.app')“ 可执行操作系统命令调出计算器。

 基于以上风险：

- 应避免外部输入的内容拼接到EL表达式或其他表达式引起、模板引擎进行解析。
- 白名单过滤外部输入，仅允许字符、数字、下划线等。

<a id="2.1.6"></a>
#### 1.6 OS命令执行

##### 1.6.1【建议】避免不可信数据拼接操作系统命令

当不可信数据存在时，应尽量避免外部数据拼接到操作系统命令使用 `Runtime` 和 `ProcessBuilder` 来执行。优先使用其他同类操作进行代替，比如通过文件系统API进行文件操作而非直接调用操作系统命令。

##### 1.6.2【必须】避免创建SHELL操作

如无法避免直接访问操作系统命令，需要严格管理外部传入参数，使不可信数据仅作为执行命令的参数而非命令。

- 禁止外部数据直接直接作为操作系统命令执行。

- 避免通过"cmd"、“bash”、“sh”等命令创建shell后拼接外部数据来执行操作系统命令。

- 对外部传入数据进行过滤。可通过白名单限制字符类型，仅允许字符、数字、下划线；或过滤转义以下符号：|;&$><`（反引号）\!

  白名单示例：

  ```java
  private static final Pattern FILTER_PATTERN = Pattern.compile("[0-9A-Za-z_]+");
  if (!FILTER_PATTERN.matcher(input).matches()) {
    // 终止当前请求的处理
  }
  ```

<a id="2.1.7"></a>
#### 1.7 会话管理

##### 1.7.1【必须】非一次有效身份凭证禁止在URL中传输

身份凭证禁止在URL中传输，一次有效的身份凭证除外（如CAS中的st）。

##### 1.7.2【必须】避免未经校验的数据直接给会话赋值

防止会话信息被篡改，如恶意用户通过URL篡改手机号码等。

<a id="2.1.8"></a>
#### 1.8 加解密

##### 1.8.1【建议】对称加密

建议使用AES，秘钥长度128位以上。禁止使用DES算法，由于秘钥太短，其为目前已知不安全加密算法。使用AES加密算法请参考以下注意事项：

- AES算法如果采用CBC模式：每次加密时IV必须采用密码学安全的伪随机发生器（如/dev/urandom）,禁止填充全0等固定值。
- AES算法如采用GCM模式，nonce须采用密码学安全的伪随机数
- AES算法避免使用ECB模式，推荐使用GCM模式。

##### 1.8.2【建议】非对称加密

建议使用RSA算法，秘钥2048及以上。

##### 1.8.3【建议】哈希算法

哈希算法推荐使用SHA-2及以上。对于签名场景，应使用HMAC算法。如果采用字符串拼接盐值后哈希的方式，禁止将盐值置于字符串开头，以避免哈希长度拓展攻击。

##### 1.8.4【建议】密码存储策略

建议采用随机盐+明文密码进行多轮哈希后存储密码。

<a id="2.1.9"></a>
#### 1.9 查询业务

##### 1.9.1【必须】返回信息最小化

返回用户信息应遵循最小化原则，避免将业务需求之外的用户信息返回到前端。

##### 1.9.2【必须】个人敏感信息脱敏展示

在满足业务需求的情况下，个人敏感信息需脱敏展示,如：

- 鉴权信息（如口令、密保答案、生理标识等）不允许展示
- 身份证只显示第一位和最后一位字符，如3****************1。
- 移动电话号码隐藏中间6位字符，如134******48。
- 工作地址/家庭地址最多显示到“区”一级。
- 银行卡号仅显示最后4位字符，如************8639		

##### 1.9.3【必须】数据权限校验

查询个人非公开信息时，需要对当前访问账号进行数据权限校验。

1. 验证当前用户的登录态
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session）。禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询。
3. 验当前用户是否具备访问数据的权限

<a id="2.1.10"></a>
#### 1.10 操作业务

##### 1.10.1【必须】部署CSRF防御机制

CSRF是指跨站请求伪造（Cross-site request forgery），是web常见的攻击之一。对于可重放的敏感操作请求，需部署CSRF防御机制。可参考以下两种常见的CSRF防御方式

- 设置CSRF Token

  服务端给合法的客户颁发CSRF Token，客户端在发送请求时携带该token供服务端校验，服务端拒绝token验证不通过的请求。以此来防止第三方构造合法的恶意操作链接。Token的作用域可以是Request级或者Session级。下面以Session级CSRF Token进行示例

  1. 登录成功后颁发Token，并同时存储在服务端Session中

     ```java
     String uuidToken = UUID.randomUUID().toString();
     map.put("token", uuidToken);
     request.getSession().setAttribute("token",uuidToken );
     return map;
     ```

     

  2. 创建Filter

     ```java
     public class CsrfFilter implements Filter {  
       ...
        HttpSession session = req.getSession();
        Object token = session.getAttribute("token");
        String requestToken = req.getParameter("token");
        if(StringUtils.isBlank(requestToken) || !requestToken.equals(token)){
              AjaxResponseWriter.write(req, resp, ServiceStatusEnum.ILLEGAL_TOKEN, "非法的token");
                 return;
             }
        ...
     ```

  ​     CSRF Token应具备随机性，保证其不可预测和枚举。另外由于浏览器会自动对表单所访问的域名添加相应的cookie信息，所以CSRF Token不应该通过Cookie传输。

  ​    

- 校验Referer头

  通过检查HTTP请求的Referer字段是否属于本站域名，非本站域名的请求进行拒绝。

  这种校验方式需要注意两点：

  1. 要需要处理Referer为空的情况，当Referer为空则拒绝请求
  2. 注意避免例如qq.com.evil.com 部分匹配的情况。

##### 1.10.2【必须】权限校验

对于非公共操作，应当校验当前访问账号进行操作权限（常见于CMS）和数据权限校验。

1. 验证当前用户的登录态
2. 从可信结构中获取经过校验的当前请求账号的身份信息（如：session）。禁止从用户请求参数或Cookie中获取外部传入不可信用户身份直接进行查询。
3. 校验当前用户是否具备该操作权限
4. 校验当前用户是否具备所操作数据的权限。避免越权。

##### 1.10.3【建议】加锁操作

对于有次数限制的操作，比如抽奖。如果操作的过程中资源访问未正确加锁。在高并发的情况下可能造成条件竞争，导致实际操作成功次数多于用户实际操作资格次数。此类操作应加锁处理。
