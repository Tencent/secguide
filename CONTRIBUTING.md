# 为 代码安全指南 作出贡献

欢迎 [提出问题或建议](issues) 或 [提交合并请求](pulls)，建议在为项目作出贡献时，阅读以下指南。

### I. Commit Mesage 编写指引

为便于索引，Commit Message应包括三个部分：Header（必需），Body（可选）和 Footer（可选）。

```html
<type>(<scope>): <subject>
// 空一行
<body>
// 空一行
<footer>
```

**Header 部分**只有一行，包括三个字段：type（必需）、scope（可选）和subject（必需）。

> type 用于说明 commit 的类别，可使用下面3个标识：<br/>
> - add: 添加新规范语言或条目<br/>
> - fix: 修订内容<br/>
> - chore: 非指南文档本身或相关辅助工具的变动<br/>
> 
> scope 用于指定 commit 影响的范围，包括对应的语言及其条目编号；如：go/1.1.1。
> 
> subject是 commit 目的的简短描述。

**Body 部分**是对本次 commit 的详细描述。

**Footer 部分**关闭 Issue。如果当前 commit 针对某个issue，可以在 Footer 部分关闭这个 issue 。

一个完整的示例如下：

```html
fix(go/1.1.1): 修订条目内容
 
- 修正代码示例缩进问题
 
Close #1
```



### II. Issues 编写指引

为便于理解与管理，提交问题或建议时，参考以下格式：

```
标题：#<对应的指南语言># 指南<对应的条目编号>修订建议

内容：
1、问题描述
<指出存在的问题>

2、解决建议
<提供解决建议及参考材料>
```

一个完整的示例如下：

```
标题：#JavaScript# 指南1.3.1条修订建议

内容：
1、问题描述
JavaScript代码安全指南的【1.3.1条】赋值或更新HTML属性部分，需补充

2、解决建议
应补充下列风险点：
area.href、input.formaction、button.formaction
```