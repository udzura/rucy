# Rucy

Rucy is a Ruby Compiler. It only supports BPF object target for now.

<img src="docs/rucy-demo.gif" width="640" />

## Usage

```ruby
license! "GPL"
section! "cgroup/dev"

class Context
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def check_device_is_urandom(ctx)
  if ctx.major == 1 && ctx.minor == 0
    return 0
  else
    return 1
  end
end
```

This is compiled into such binary, with valid BPF metadata:

```console
$ rucy object ./check_urandom.rb --dest result.o
```

```console
$ llvm-objdump -d result.o 

result.o:       file format elf64-bpf


Disassembly of section cgroup/dev:

0000000000000000 <check_device_is_urandom>:
       0:       bf 13 00 00 00 00 00 00 r3 = r1
       1:       61 33 04 00 00 00 00 00 r3 = *(u32 *)(r3 + 4)
       2:       b7 04 00 00 01 00 00 00 r4 = 1
       3:       1f 43 00 00 00 00 00 00 r3 -= r4
       4:       55 03 04 00 00 00 00 00 if r3 != 0 goto +4 <check_device_is_urandom+0x48>
       5:       bf 13 00 00 00 00 00 00 r3 = r1
       6:       61 33 08 00 00 00 00 00 r3 = *(u32 *)(r3 + 8)
       7:       b7 04 00 00 00 00 00 00 r4 = 0
       8:       1f 43 00 00 00 00 00 00 r3 -= r4
       9:       55 03 02 00 00 00 00 00 if r3 != 0 goto +2 <check_device_is_urandom+0x60>
      10:       b7 03 00 00 00 00 00 00 r3 = 0
      11:       05 00 01 00 00 00 00 00 goto +1 <check_device_is_urandom+0x68>
      12:       b7 03 00 00 01 00 00 00 r3 = 1
      13:       bf 30 00 00 00 00 00 00 r0 = r3
      14:       95 00 00 00 00 00 00 00 exit

```

## Demo

* https://twitter.com/i/status/1430046852699680769

## TODO

* Integrate into libbpf
* More binary targets, e.g. llvm-IR, web assembly, ...
