// to run this script use:
// frida -U  -l script.js -f <name of the package>
// e.g.: frida -U -l script.js -f com.supersecure.sample

Java.perform(() => {
	let isListenerAttached = false;
	const class1 = Java.use("com.stringcare.library.StringExtKt");
//    class1.revealV3.overload('android.content.Context','int','boolean').implementation = function(p1, p2, p3){
//    class1.reveal.overload('int','boolean','com.stringcare.library.Version').implementation = function(p1, p2, p3) {
	
	class1.reveal$default.overload('int', 'boolean', 'com.stringcare.library.Version', 'int', 'java.lang.Object').implementation = function(p1, p2, p3,p4,p5) {
		console.log("params below:")

		if (!isListenerAttached) {
			Interceptor.attach(Module.findExportByName("libsc-native-lib.so", "Java_com_stringcare_library_SC_jniRevealV3"), {
				onEnter: function(args) {
			 		console.log("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB1111")	
			 		console.log(args[0])	
			 		console.log(args[1])	
			 		console.log(args[2])	
			 		console.log(args[3])	
			 		console.log(args[4])	
				},
				onLeave: function(retVal) {
			 		console.log("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB222222")	
					console.log(retVal)
				}
			})
		}

       		const res = this.reveal$default(2131427370,p2,p3,p4,p5)
       		console.log("res below:")
       		console.log(res)

       		return res;
   };
});
