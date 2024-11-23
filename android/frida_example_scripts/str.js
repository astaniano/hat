// to run this script use:
// frida -U  -l script.js -f <name of the package>
// e.g.: frida -U -l script.js -f com.supersecure.sample

Java.perform(() => {
	const class1 = Java.use("android.content.Context");
//    class1.revealV3.overload('android.content.Context','int','boolean').implementation = function(p1, p2, p3){
//	class1.reveal$default.overload('int', 'boolean', 'com.stringcare.library.Version', 'int', 'java.lang.Object').implementation = function(p1, p2, p3,p4,p5) {
	
    class1.getString.overload('int').implementation = function(p1) {
		console.log("params below:")
       		console.log(p1)
		
       		const res = this.getString(p1)
       		console.log("res below:")
       		console.log(res)

       		return "-64, -125";
   };
});
