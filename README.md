# Why create my own obfuscator

I need a java obfuscator that can process class file directly but I'm unable to find anything useful, 

1. proguard: most widely applied in the java world, but no string encryption, no control flow obfuscation, not a good candidate.
2. [yWorks/yGuard](https://github.com/yWorks/yGuard): very bad user support, code is not portable, can't work without a pipeline.
3. [superblaubeere27/obfuscator](https://github.com/superblaubeere27/obfuscator): the only thing works, but with very high memory requirements and the code is totally garbage. Most importantly can't process class files, only for jar files and gui is enforced.

So let's create a dead simple obfuscator SDK, using the same ASM + Javassist technique but with better code quality.

# Scenarios

Obfuscate your java payload and in-memory webshells in the fly :-)

# Available features

1. Replace all method names, local variable names and class properties
2. Encrypt all strings, create your own encrypt and decrypt code stub!

# How to use this repo

I have two methods exposed for you, should work in 99% cases.

```java
public byte[] processClassFile(String fileName) throws Exception {}
public byte[] processClassBytes(byte[] classBytes) throws IOException, CannotCompileException {}
```
