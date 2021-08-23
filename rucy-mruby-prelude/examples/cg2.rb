license! "GPL"
section! "dev/cgroup"

class Ctx
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def prog(ctx)
  if ctx.minor == 9
    return 0
  else
    return 1
  end
end
