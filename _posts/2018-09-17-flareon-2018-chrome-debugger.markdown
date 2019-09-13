---
layout: post
title:  "FlareOn 2018 Level 5 - Solving WebAssembly Crackme (Part I - Recompilation and Chrome)"
date:   2018-09-16 18:03:59
categories: reverse
---

Level 5 of FlareOn 2018 was a [WebAssembly](https://webassembly.org/) crackme challenge where we were handed a compiled wasm file and told to extract the password. Here we will look into two different ways of solving this challenge: ReCompilation to x86 (this blog post) and using a new dynamic-analysis framework called [Wasabi](http://wasabi.software-lab.org/) (next blog post).

## Recon

We begin with 3 files provided by the organizers:

```
$ ls
index.html main.js    test.wasm
```

The `index.html` is simply a loader for the `main.js` file:

```python
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
</body>
</html>
```

The `main.js` is the file that will instantiate the `test.wasm` file. This is effectively loading the `test.wasm` file and calling a given export from the file.

```js
fetch("test.wasm").then(response =>
  response.arrayBuffer()
).then(bytes =>
  WebAssembly.instantiate(bytes, {
  ...
```

The crux of the `main.js` is below:

```js
let a = new Uint8Array([
    0xE4, 0x47, 0x30, 0x10, 0x61, 0x24, 0x52, 0x21, 0x86, 0x40, 0xAD, 0xC1, 0xA0, 0xB4, 0x50, 0x22, 0xD0, 0x75, 0x32, 0x48, 0x24, 0x86, 0xE3, 0x48, 0xA1, 0x85, 0x36, 0x6D, 0xCC, 0x33, 0x7B, 0x6E, 0x93, 0x7F, 0x73, 0x61, 0xA0, 0xF6, 0x86, 0xEA, 0x55, 0x48, 0x2A, 0xB3, 0xFF, 0x6F, 0x91, 0x90, 0xA1, 0x93, 0x70, 0x7A, 0x06, 0x2A, 0x6A, 0x66, 0x64, 0xCA, 0x94, 0x20, 0x4C, 0x10, 0x61, 0x53, 0x77, 0x72, 0x42, 0xE9, 0x8C, 0x30, 0x2D, 0xF3, 0x6F, 0x6F, 0xB1, 0x91, 0x65, 0x24, 0x0A, 0x14, 0x21, 0x42, 0xA3, 0xEF, 0x6F, 0x55, 0x97, 0xD6
]);

let b = new Uint8Array(new TextEncoder().encode(getParameterByName("q")));

let pa = wasm_alloc(instance, 0x200);
wasm_write(instance, pa, a);

let pb = wasm_alloc(instance, 0x200);
wasm_write(instance, pb, b);

if (instance.exports.Match(pa, a.byteLength, pb, b.byteLength) == 1) {
    // PARTY POPPER - Success
} else {
    // PILE OF POO - Fail
}
```

Some piece of ciphertext is allocated via `wasm_alloc` as well as the input passed by the `q` parameter. These two sections of data are passed to the `Match` function exported from `test.wasm`. We can see this is the `Match` function via `instance.exports.Match`. Our goal is to reverse the Match function in order for it to return `1`.

## Disassembling WASM

We can leverage the low-level tools provided by WebAssembly called [wabt](https://github.com/WebAssembly/wabt) to begin analysis of `test.wasm`. Let's begin with building the tools.

```
$ git clone --recursive https://github.com/WebAssembly/wabt
$ cd wabt
$ make
```

The tools can be found in `./out/clang/Debug`. We can confirm that the `Match` function is actually an exported function from `test.wasm`.

```
$ ./out/clang/Debug/wasm-objdump -x -j Export ./test.wasm

test.orig.wasm: file format wasm 0x1

Section Details:

Export[6]:
 - func[48] <Match> -> "Match"
 - func[49] <writev_c> -> "writev_c"
 - table[0] -> "__wasabi_table"
 - memory[0] -> "memory"
 - global[1] -> "__heap_base"`
 - global[2] -> "__data_end"
```

From here, we could begin analyzing the disassembly at the `Match` function.

```
$ ./out/clang/Debug/wasm-objdump -j Code -d ./test.wasm | rg -A10 Match

005ecf <Match>:
005ed2: 4b 7f                      | local[0..74] type=i32
005ed4: 41 0a                      | i32.const 10
005ed6: 41 7f                      | i32.const 4294967295
005ed8: 10 01                      | call 1 <begin_function>
005eda: 23 00                      | get_global 0
005edc: 41 0a                      | i32.const 10
005ede: 41 00                      | i32.const 0
005ee0: 41 00                      | i32.const 0
005ee2: 23 00                      | get_global 0
005ee4: 10 02                      | call 2 <get_global_i>
005ee6: 21 04                      | set_local 4
005ee8: 41 0a                      | i32.const 10
005eea: 41 01                      | i32.const 1
005eec: 41 04                      | i32.const 4
005eee: 20 04                      | get_local 4
005ef0: 10 03                      | call 3 <set_local_i>
005ef2: 41 20                      | i32.const 32
005ef4: 41 0a                      | i32.const 10
005ef6: 41 02                      | i32.const 2
005ef8: 41 20                      | i32.const 32
```

While this `objdump` output can definitely be analyzed, we can do better. Using the same `wabt` tools, we can recompile this wasm into x86, which is a bit easier to read. The `wasm2c` tool can be used to create an extensive `.c` file.

```
# Create test.c
./out/clang/Debug/wasm2c test.wasm -o test.c
```

With the `test.c`, we can then compile with the headers provided by `wabt`.

```
# Create binary
gcc -m32 -o flareon_level5 -I$PWD/wasm2c wasm2c/wasm-rt-impl.c test.c
```

We now have a binary that we can analyze. The goal here is to reverse a bit and then leverage a browser debugger to possibly gain runtime information about what is being checked. Note that this compilation is not optimized, because optimizations will make it a bit harder to go back to the wasm for setting breakpoints in the debugger.

In [Binary Ninja](https://binary.ninja/), we now have a binary that looks something like the following:

![binja1.jpg](/assets/images/flareon2018-level5/binja1.jpg)

In [Hex Rays](https://www.hex-rays.com/), we have something like the following:

![hexrays1.jpg](/assets/images/flareon2018-level5/hexrays1.jpg)

This gives us the ability to rename variables, add struct types, ect making it just a bit easier to reverse.

We can see the main function that `Match` calls is `f9`. This function must be doing the bulk of the analysis. In `f9` there is a data processing loop that calls some dynamic function. The result of this function is then compared with a memory value:

![hexrays1.jpg](/assets/images/flareon2018-level5/hexrays2.jpg)

There are usually two possible conditions for crackmes like this that we can use to make a further assumption:

* The ciphertext is decoded and then the plaintext is checked in memory
* The password is encoded and the encoded password is checked against the ciphertext in memory

The first is easier to check of the two. If we assume this comparison is actually a case of the first bullet point, a simple breakpoint at the comparison will tell us the password. With this test in mind, we need to go backwards from the x86 to the wasm to find a useful breakpoint.

Here we use context clues to give us an interesting breakpoint location.

```c
v19 = i32_load(&memory, v32 + 24, 0) + v18;
if ( v16 == (char)i32_load8_u(&memory, v19, 0) )
```

We want to look for an instance of `i32_load8_u` that comes after a `i32.load` with `offset=24`. This could be found with `objdump` like before, but in practice, I simply looked in Chrome for this pattern and set a breakpoint.

To debug this in Chrome, start a simple HTTP server in the folder where the problem files are located:

```
$ ls
index.html    main.js       test.wasm     web2point0.7z

$ python -m SimpleHTTPServer 8888
Serving HTTP on 0.0.0.0 port 8888 ...
```

In Chrome, navigate to `http://localhost:8888/index.html?q=QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ` to start the problem with some value in `q`.

Chrome comes with a WASM debugger. Right-click and click on `Inspect` on the page after it is loaded and click on the `Sources` tab.

![chrome1.jpg](/assets/images/flareon2018-level5/chrome1.jpg)

We can also see the various functions called by `test.wasm` that Chrome gives us as well.

![chrome2.jpg](/assets/images/flareon2018-level5/chrome2.jpg)

Using our reversing knowledge, we can go into `f9` and look for that particular `i32_load8_u`.

![chrome3.jpg](/assets/images/flareon2018-level5/chrome3.jpg)

Clicking on the `300` number will set a breakpoint on this instruction. We can now throw our `Q` string to see if those `Q`s are being directly compared against the (assumed) decrypted string.

![chrome4.jpg](/assets/images/flareon2018-level5/chrome4.jpg)

The contents of the stack we see are 119 (or `w`) and 81 (or `Q`). Continuing from this breakpoint 5 times, we end up with `wasm_`. This gives us higher hopes that we are on the right path. By continuing and recording the stack at each iteration we eventually conclude with the flag:

```python
a = [119, 97, 115, 109, 95, 114, 117, 108, 101, 122, 95, 106, 115, 95, 100, 114, 111, 111, 108, 122, 64, 102, 108, 97, 114, 101, 45, 111, 110, 46, 99, 111, 109]
print(''.join(chr(x) for x in a))

'wasm_rulez_js_droolz@flare-on.com'
```
