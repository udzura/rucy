license! "GPL"
section! "dev/cgroup"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  if ctx.major == 1
    bpf_trace_printk("Access to character device detected. R/W: %d", ctx.access_type)
  end
  return 1
end
