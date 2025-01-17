var deparam = function (params, coerce) {
  let obj = {};
  let cur = obj;
  let keys = ["__proto__", "random1"];
  let keys_last = 1;
  let val = "random2";

  for (let i = 0; i <= keys_last; i++) {
    key = keys[i];

    let temp = i < keys_last ? cur[key] : val;

    cur[key] = temp;

    cur = cur[key];
  }

  return obj;
};
