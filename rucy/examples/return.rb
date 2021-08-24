license! "GPL"
section! "cgroup/dev"

class Context
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  return 0
end
