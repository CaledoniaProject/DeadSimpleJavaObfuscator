import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.FieldVisitor;
import org.objectweb.asm.Handle;
import org.objectweb.asm.Label;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;

import javassist.CannotCompileException;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import javassist.CtNewMethod;
import javassist.bytecode.Opcode;

public class Obfuscator {
    public Obfuscator() {
    }

    public Set<String> getClassMethods(String className) throws IOException {
        Set<String> methods = new HashSet<>();
        ClassReader classReader = new ClassReader(className);

        classReader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                    String[] exceptions) {
                methods.add(name + ":" + descriptor);
                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
        }, 0);

        return methods;
    }

    public String getRandomVariableName() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        return randomString(chars, 20);
    }

    public String getRandomEncryptionKey() {
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890";
        return randomString(chars, 32);
    }

    public String randomString(String chars, int length) {
        StringBuilder sb = new StringBuilder();
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < length; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }

        return sb.toString();
    }

    public String encryptString(String clearText, String encryptionKey) throws Exception {
        return Base64.getEncoder().encodeToString(clearText.getBytes());
    }

    public byte[] addDecryptMethod(byte[] classBytes) throws IOException, CannotCompileException {
        ClassPool classPool = new ClassPool();
        classPool.appendSystemPath();
        classPool.importPackage("javax.crypto.Cipher");
        classPool.importPackage("javax.crypto.spec.SecretKeySpec");
        classPool.importPackage("javax.crypto.spec.IvParameterSpec");
        classPool.importPackage("java.util.Base64");

        CtClass ctClass = classPool.makeClass(new ByteArrayInputStream(classBytes));
        ctClass.defrost();

        String methodCode = 
        "public static String decryptString(String cipherText, String encryptionKey) throws Exception {\n"
            "return new String(Base64.getDecoder().decode(cipherText), \"UTF-8\");\n" +
        "}\n";

        CtMethod method = CtNewMethod.make(methodCode, ctClass);
        ctClass.addMethod(method);

        byte[] modifiedClassBytes = ctClass.toBytecode();

        ctClass.detach();
        return modifiedClassBytes;
    }

    public byte[] processClassFile(String fileName) throws Exception {
        byte[] classBytes = Files.readAllBytes(Paths.get(fileName));
        return processClassBytes(classBytes);
    }

    public byte[] processClassBytes(byte[] classBytes) throws IOException, CannotCompileException {
        final String encryptMethodName = "decryptString";
        final String encryptMethodDescriptor = "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;";
        final String encryptMethodNameKey = encryptMethodName + ":" + encryptMethodDescriptor;
        final Set<String> excludedMethods = new HashSet<>();
        final Map<String, String> globalFieldMap = new HashMap<>();
        final Map<String, String> globalMethodMap = new HashMap<>();

        classBytes = addDecryptMethod(classBytes);

        ClassReader classReader = new ClassReader(new ByteArrayInputStream(classBytes));
        ClassWriter classWriter = new ClassWriter(ClassWriter.COMPUTE_FRAMES);

        String currentClassName = classReader.getClassName();

        classReader.accept(new ClassVisitor(Opcodes.ASM9) {
            @Override
            public void visit(int version, int access, String name, String signature, String superName,
                    String[] interfaces) {
                try {
                    excludedMethods.addAll(getClassMethods(superName));
                    for (String interfaceName : interfaces) {
                        Set<String> methods = getClassMethods(interfaceName);
                        excludedMethods.addAll(methods);
                    }
                } catch (IOException e) {
                    e.printStackTrace();
                }

                super.visit(version, access, name, signature, superName, interfaces);
            }

            @Override
            public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
                globalFieldMap.put(name + ":" + descriptor, getRandomVariableName());
                return super.visitField(access, name, descriptor, signature, value);
            }

            @Override
            public MethodVisitor visitMethod(int access, String name, String descriptor, String signature,
                    String[] exceptions) {
                  if (!"<init>".equals(name)
                        && !"<clinit>".equals(name)
                        && !"main".equals(name)
                        && !name.startsWith("lambda$")
                        && !excludedMethods.contains(name + ":" + descriptor)) {
                    globalMethodMap.put(name + ":" + descriptor, getRandomVariableName());
                }

                return super.visitMethod(access, name, descriptor, signature, exceptions);
            }
        }, 0);

        classReader.accept(new ClassVisitor(Opcodes.ASM9, classWriter) {
            @Override
            public FieldVisitor visitField(int access, String name, String descriptor, String signature, Object value) {
                String newName = globalFieldMap.get(name + ":" + descriptor);
                if (newName == null) {
                    newName = name;
                }

                return super.visitField(access, newName, descriptor, signature, value);
            }

            @Override
            public MethodVisitor visitMethod(int access, String currentMethodName, String descriptor, String signature,
                    String[] exceptions) {
                String newName = globalMethodMap.get(currentMethodName + ":" + descriptor);
                if (newName == null) {
                    newName = currentMethodName;
                }

                MethodVisitor mv = super.visitMethod(access, newName, descriptor, signature, exceptions);

                return new MethodVisitor(Opcodes.ASM9, mv) {
                    @Override
                    public void visitInvokeDynamicInsn(String name, String descriptor, Handle bootstrapMethodHandle,
                            Object... bootstrapMethodArguments) {
                        super.visitInvokeDynamicInsn(name, descriptor, bootstrapMethodHandle, bootstrapMethodArguments);
                    }

                    @Override
                    public void visitParameter(String name, int access) {
                        String newName = getRandomVariableName();
                        super.visitParameter(newName, access);
                    }

                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String descriptor,
                            boolean isInterface) {
                        if (owner.equals(currentClassName)) {
                            String newMethodName = globalMethodMap.get(name + ":" + descriptor);
                            if (newMethodName != null) {
                                super.visitMethodInsn(opcode, owner, newMethodName, descriptor, isInterface);
                                return;
                            }
                        }

                        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (currentMethodName.equals(encryptMethodName)) {
                            super.visitLdcInsn(value);
                            return;
                        }

                        if (value instanceof String) {
                            try {
                                String clearText = (String) value;
                                if (clearText.isEmpty()) {
                                    super.visitLdcInsn(value);
                                    return;
                                }

                                String methodName = globalMethodMap.get(encryptMethodNameKey);
                                String encryptionKey = getRandomEncryptionKey();
                                String newString = encryptString(clearText, encryptionKey);

                                super.visitLdcInsn(newString);
                                super.visitLdcInsn(encryptionKey);
                                super.visitMethodInsn(Opcode.INVOKESTATIC, currentClassName, methodName,
                                        encryptMethodDescriptor, false);
                            } catch (Exception e) {
                                e.printStackTrace();
                            }
                        } else {
                            super.visitLdcInsn(value);
                        }
                    }

                    @Override
                    public void visitLocalVariable(String name, String descriptor, String signature, Label start,
                            Label end, int index) {
                        String newLocalName = getRandomVariableName();
                        super.visitLocalVariable(newLocalName, descriptor, signature, start, end, index);
                    }

                    @Override
                    public void visitFieldInsn(int opcode, String owner, String name, String descriptor) {
                        String newFieldName = globalFieldMap.get(name + ":" + descriptor);
                        if (newFieldName == null) {
                            newFieldName = name;
                        }

                        super.visitFieldInsn(opcode, owner, newFieldName, descriptor);
                    }
                };
            }
        }, 0);

        return classWriter.toByteArray();
    }
}
