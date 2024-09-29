// https://medium.com/swlh/exploring-native-functions-with-frida-on-android-part-1-bf93f0bfa1d3
// https://mobsecguys.medium.com/exploring-native-functions-with-frida-on-android-part-2-98b97e89eb3d
// https://mobsecguys.medium.com/exploring-native-functions-with-frida-on-android-part-3-45422ae18caa
// https://medium.com/swlh/exploring-native-functions-with-frida-on-android-part-4-22db2c247e29
//
// frida -Uf [package_name] -l myScript.js
// frida -Uf com.supersecure.sample -l ns.js


// ** Find modules that are loaded during the app startup (but not during runtime)
//
// const modulesArr = Process.enumerateModules() 
// 
// for (const mod of modulesArr) {
// 	if (mod.path.includes('sc')) {
// 		console.log(JSON.stringify(mod))
// 	}
// }


// ** Find module during app runtime i.e.: module was loaded after something happened, e.g. user clicked on a btn
//
// Interceptor.attach(Module.findExportByName(null, "open"), {
// 	onEnter: function(args) {
// 		let str = args[0].readUtf8String();	
// 		if (str.includes('.so')) {
// 			// str example: /data/app/com.supersecure.sample-1/lib/x86_64/libsc-native-lib.so
// 			const split = str.split('/')
// 			const libName = split[split.length - 1]
// 			console.log(libName)
// 			const mod2 = Process.findModuleByName(libName)
// 			// mod2 here was null during testing, dunno why
// 			if (mod2 != null) {
// 				console.log("found mod")
// 				const exports = module.enumerateExports();	
// 				for (const exp of exports) {
// 					console.log(exp)
// 				}
// 			}
// 		}
// 	}
// })


// ** Load module explicity (doesn't matter if it is loaded by the app or not, we're loading it ourselfs)
//
const mod1 = Module.load("/data/app/com.supersecure.sample-1/lib/x86_64/libsc-native-lib.so")
// console.log(JSON.stringify(mod1))

const exports = mod1.enumerateExports();
for (const exp of exports) {
	if (exp.name.includes("eveal")) {
		//console.log(JSON.stringify(exp))
	}
}

const expAddr = Module.findExportByName("libsc-native-lib.so", "Java_com_stringcare_library_SC_jniRevealV3")
console.log(expAddr)
Interceptor.attach(expAddr, {
	onEnter: function(args) {
		console.log("func has been called")
		console.log("func has been called")
		console.log("func has been called")
		console.log(args)
	},
	onEnter: function(retVal) {}
})


// ** interesting but didn't work for some reason
//
// Interceptor.attach(Module.findExportByName("libc.so", "open"), {
// 	onEnter: function(args) {
//  		const str = args[0].readUtf8String();	
// 		if (str === "/data/app/com.supersecure.sample-1/lib/x86_64/libsc-native-lib.so") {
//             		Process.enumerateModules({
//             		    onMatch: function(module) {
//             		        if (module.name.includes("sc")) {
//             		            console.log("Module found: ", module);
//             		        }
//             		    },
//             		    onComplete: function() {
//             		        console.log("Module enumeration complete.");
//             		    }
//             		});
// 
// 			// const expAddr = Module.findExportByName("libsc-native-lib.so", "Java_com_stringcare_library_SC_jniRevealV3")
// 		}
// 	}
// })
