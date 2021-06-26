# rucy

Ruby DSL to BPF CO-RE tools

## Usage-to-be

```ruby
Rucy.build do |prog|
  prog.license "GPL"
  prog.section "cgroup/dev"
  prog.args    [
    "struct bpf_cgroup_dev_ctx",
    [:u32, "access_type"], [:u32, "major"], [:u32, "minor"]
  ]
  prog.function do |ctx|
    if ctx.major == 1 && ctx.minor == 0
      return 0
    else
      return 1
    end
  end
end

cgroup_path = ARGV[0]
obj, prog_fd = BPF.prog_load(Rucy.program)
cgroup_fd = File.open(cgroup_path, "r")

BPF.prog_attach(prog_fd, cgroup_fd, Rucy.prog_type)
puts "BPF attached: #{cgroup_path}"
exit 0
```
