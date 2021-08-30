license! "GPL"
section! "cgroup/dev"

class Context
  attr :access_type, :u32
  attr :major, :u32
  attr :minor, :u32
end

def check_device_is_urandom(ctx)
  if ctx.minor == 0
    return 0
  else
    return 1
  end
end
