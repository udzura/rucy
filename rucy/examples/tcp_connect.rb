license! "GPL"

class Sock
  attr :sk_addrpair, :u64
  attr :skc_hash,    :u32
  # ...
end

section! "kprobe/tcp_connect"
def prog(sock)
  bpf_trace_printk("TCP connect invoked\n", 21)
  return 0
end
