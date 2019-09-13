---
layout: post
title:  "FlareOn 2018 Level 5 - Solving WebAssembly Crackme (Part II - Wasabi)"
date:   2018-09-16 18:03:59
categories: reverse
---

Level 5 of FlareOn 2018 was a [WebAssembly](https://webassembly.org/) crackme challenge where we were handed a compiled wasm file and told to extract the password. Here we will look into two different ways of solving this challenge: ReCompilation to x86 (previous blog post) and using a new dynamic-analysis framework called Wasabi (this blog post).

Taken from the previous post:

```
There are usually two possible conditions for crackmes like this that we can use to make a further assumption:

* The ciphertext is decoded and then the plaintext is checked in memory
* The password is encoded and the encoded password is checked against the ciphertext in memory
```

Using the first assumption, we can quickly check if this is true using the [Wasabi](http://wasabi.software-lab.org/) framework.

## Installation

The [Wasabi GitHub page](https://github.com/danleh/wasabi) shows the installation instructions. If you don't want to install `wasabi` locally, I've put together a quick Docker image that can be used to generate the hooks.

```
$ docker pull ctfhacker/wasabi
```

Wasabi takes a single `.wasm` file and generates a hooked `.wasm` file as well as a `.js` file that can communicate with the generated hooks. These bindings can be generated with the docker image above:

```
$ docker run --rm -v `pwd`:/data -t ctfhacker/wasabi /data/test.wasm /data/out
```

In `out/` in the local directory will now be two new files: `test.wasabi.js` and `test.wasm`. We can now test the problem from this directory. Let's copy over the relavant files into this directory for further analysis.

```
cp ../index.html .
cp ../main.js .
```

We now need to edit the `index.html` to include the Wasabi hooks.

```
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <style>
  </style>
</head>
<body>
  <span id="container"></span>
  <script src="./main.js"></script>
  <script src="./test.wasabi.js"></script>
</body>
</html>
```

We can start a HTTP server and send a sample input to the problem to confirm that we are getting Wasabi hooks now. 

```
python -m SimpleHTTPServer
wget http://127.0.0.1:8000?q=QQQQQQQQQQQQQQQQQQQQQQQ
```

If everything goes great, we should see a few warning messages in the `Console` of the Developer Tools in Chrome.

```
test.wasabi.js:141 start hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 if_ hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 br hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 br_if hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 br_table hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 begin hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 end hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 nop hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 unreachable hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 drop hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 select hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 call_pre hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 call_post hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 return_ hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 const_ hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 unary hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 binary hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 load hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 store hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 memory_size hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 memory_grow hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 local hook not provided by Wasabi.analysis, add empty function as fallback
test.wasabi.js:141 global hook not provided by Wasabi.analysis, add empty function as fallback
```

We now have hooks installed and can use one of the included analysis scripts given to us by the Wasabi team. One such analysis just logs information about the various hooks. We can pull it down and add it to the problem.

```
wget https://raw.githubusercontent.com/danleh/wasabi/master/analyses/log-all.js .
```

Let's add this `log-all.js` analysis to our `index.html`. 

```
<!DOCTYPE html>
<html>
<head>
  <meta charset='utf-8'>
  <style>
  </style>
</head>
<body>
  <span id="container"></span>
  <script src="./main.js"></script>
  <script src="./test.wasabi.js"></script>
  <script src="./log-all.js"></script>
</body>
</html>
```

This analysis will simply log the arguments coming to each hook. Rerunning the challenge with the `log-all.js` results in some interesting output in the Console in Chrome.

```js
{func: 47, instr: 2099} "i32.eq" "first =" 119 " second =" 81 "result =" 0
```

Here we find a comparison operation comparing with an input `Q`. Let's modify the `log-all.js` file so we only return these operations.

```js
result = ''

Wasabi.analysis = {
    binary(location, op, first, second, r) {
        if (op == 'i32.eq') {
            result += String.fromCharCode(first);
            console.log(location, op, "first =", first, " second =", second, "result =", r);
            console.log(result);
        }
    }
};
```

Rerunning the analysis with the the same input gives us an unexpected result.

```
log-all.js:11 Object "i32.eq" "first =" 119 " second =" 110 "result =" 0
log-all.js:12 w
log-all.js:11 Object "i32.eq" "first =" 119 " second =" 110 "result =" 0
log-all.js:12 ww
log-all.js:11 Object "i32.eq" "first =" 97 " second =" 117 "result =" 0
log-all.js:12 wwa
log-all.js:11 Object "i32.eq" "first =" 97 " second =" 117 "result =" 0
log-all.js:12 wwaa
log-all.js:11 Object "i32.eq" "first =" 115 " second =" 108 "result =" 0
log-all.js:12 wwaas
log-all.js:11 Object "i32.eq" "first =" 115 " second =" 108 "result =" 0
log-all.js:12 wwaass
log-all.js:11 Object "i32.eq" "first =" 109 " second =" 108 "result =" 0
log-all.js:12 wwaassm
log-all.js:11 Object "i32.eq" "first =" 109 " second =" 108 "result =" 0
log-all.js:12 wwaassmm
```

Oop, looks like there are two different comparisons that we are recording. Let's simplify and only record on one of these instances.

```js
result = ''

Wasabi.analysis = {
    binary(location, op, first, second, r) {
        if (op == 'i32.eq' && location['func'] == 47) {
            result += String.fromCharCode(first);
            console.log(location, op, "result =", result);
        }
    }
};
```

With this simplification, we are given the flag one character at a time.

```js
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "w"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wa"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "was"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_r"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_ru"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rul"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rule"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_j"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_d"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_dr"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_dro"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droo"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_drool"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@f"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@fl"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@fla"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flar"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-o"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-on"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-on."
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-on.c"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-on.co"
log-all.js:12 {func: 47, instr: 2099} "i32.eq" "result =" "wasm_rulez_js_droolz@flare-on.com"
```

