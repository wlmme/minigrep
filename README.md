# minigrep - 字符串搜索工具
一个使用Rust实现的命令行工具，用于在文件中搜索指定的字符串，支持正则表达式，支持多路径递归搜索。

## 功能特性
- 支持正则表达式搜索
- 支持多路径递归搜索
- 支持忽略大小写搜索

## Next to do
- 添加字符串查找优化，判断表达式是否是正则匹配
- 添加匹配结果流式处理，不收集结果排序后再打印
- 添加SIMD优化的字符串查找
- 添加大文件分块查找字符串并解决边界问题
- 添加单元测试和集成测试
- 添加性能测试和相关文档